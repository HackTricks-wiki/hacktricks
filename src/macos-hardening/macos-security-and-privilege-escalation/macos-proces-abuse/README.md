# Зловживання процесами macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація про процеси

Процес є екземпляром виконуваного файлу, що працює, однак код виконують не процеси, а потоки. Тому **процеси є лише контейнерами для потоків, що виконуються**, і надають їм пам'ять, дескриптори, порти, дозволи...

Традиційно процеси запускалися всередині інших процесів (крім PID 1) викликом **`fork`**, який створює точну копію поточного процесу, після чого **дочірній процес** зазвичай викликає **`execve`**, щоб завантажити новий виконуваний файл і запустити його. Потім було представлено **`vfork`**, щоб пришвидшити цей процес без копіювання пам'яті.\
Пізніше було представлено **`posix_spawn`**, який об'єднує **`vfork`** і **`execve`** в одному виклику та приймає прапорці:

- `POSIX_SPAWN_RESETIDS`: Скинути ефективні ідентифікатори до реальних ідентифікаторів
- `POSIX_SPAWN_SETPGROUP`: Встановити належність до групи процесів
- `POSUX_SPAWN_SETSIGDEF`: Встановити поведінку сигналів за замовчуванням
- `POSIX_SPAWN_SETSIGMASK`: Встановити маску сигналів
- `POSIX_SPAWN_SETEXEC`: Виконати exec у тому самому процесі (як `execve`, але з додатковими параметрами)
- `POSIX_SPAWN_START_SUSPENDED`: Запустити призупиненим
- `_POSIX_SPAWN_DISABLE_ASLR`: Запустити без ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Використовувати Nano allocator із libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Дозволити `rwx` для сегментів даних
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Типово закривати всі файлові описи під час exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Рандомізувати старші біти зсуву ASLR

Крім того, `posix_spawn` приймає параметри **`posix_spawnattr`**, які керують аспектами породженого процесу, а також записи **`posix_spawn_file_actions`**, що змінюють файлові дескриптори.

Коли процес завершується, він надсилає **код повернення батьківському процесу** (якщо батьківський процес завершився, новим батьківським процесом стає PID 1) за допомогою сигналу `SIGCHLD`. Батьківський процес має отримати це значення, викликавши `wait4()` або `waitid()`, і до цього моменту дочірній процес перебуває у стані zombie: він усе ще відображається у списку, але не споживає ресурси.

### PID

PID, ідентифікатор процесу, однозначно ідентифікує процес. У XNU **PID** мають розмір **64 біти**, збільшуються монотонно та **ніколи не переповнюються** (для запобігання зловживанням).

### Групи процесів, сесії та coalations

**Процеси** можна об'єднувати в **групи**, щоб спростити керування ними. Наприклад, команди у shell-скрипті перебувають в одній групі процесів, тому їх можна **одночасно надсилати їм сигнал** за допомогою kill.\
Також можна **об'єднувати процеси в сесії**. Коли процес запускає сесію (`setsid(2)`), дочірні процеси додаються до цієї сесії, якщо тільки вони не запускають власну сесію.

Coalition — це ще один спосіб групування процесів у Darwin. Приєднання процесу до coalition дає йому доступ до спільних ресурсів пулу, спільного ledger або наражає його на Jetsam. Coalitions мають різні ролі: Leader, XPC service, Extension.

### Облікові дані та personae

Кожен процес **має облікові дані**, які **визначають його привілеї** в системі. Кожен процес має один основний `uid` і один основний `gid` (хоча він може належати до кількох груп).\
Також можна змінити ідентифікатор користувача та групи, якщо бінарний файл має біт `setuid/setgid`.\
Існує кілька функцій для **встановлення нових uid/gid**.

Системний виклик **`persona`** надає альтернативний набір **облікових даних**. Прийняття persona одночасно встановлює її uid, gid і членство в групах. У [**вихідному коді**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) можна знайти структуру:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Основна інформація про потоки

1. **POSIX Threads (pthreads):** macOS підтримує POSIX-потоки (`pthreads`), які є частиною стандартного API для роботи з потоками в C/C++. Реалізація pthreads у macOS розташована в `/usr/lib/system/libsystem_pthread.dylib` і походить із загальнодоступного проєкту `libpthread`. Ця бібліотека надає необхідні функції для створення потоків і керування ними.
2. **Створення потоків:** Функція `pthread_create()` використовується для створення нових потоків. Усередині ця функція викликає `bsdthread_create()`, системний виклик нижчого рівня, специфічний для ядра XNU (ядра, на якому базується macOS). Цей системний виклик приймає різні прапорці, отримані з `pthread_attr` (атрибутів), які визначають поведінку потоку, зокрема політики планування та розмір стека.
- **Розмір стека за замовчуванням:** Розмір стека за замовчуванням для нових потоків становить 512 КБ, чого достатньо для типових операцій, але його можна змінити за допомогою атрибутів потоку, якщо потрібно більше або менше місця.
3. **Ініціалізація потоку:** Функція `__pthread_init()` має вирішальне значення під час налаштування потоку. Вона використовує аргумент `env[]` для аналізу змінних середовища, які можуть містити відомості про розташування та розмір стека.

#### Завершення потоків у macOS

1. **Вихід із потоків:** Зазвичай потоки завершуються викликом `pthread_exit()`. Ця функція дає потоку змогу коректно завершити роботу, виконати необхідне очищення та передати значення, що повертається, будь-яким потокам, які очікують його завершення.
2. **Очищення потоку:** Після виклику `pthread_exit()` викликається функція `pthread_terminate()`, яка обробляє видалення всіх пов’язаних із потоком структур. Вона звільняє порти потоків Mach (Mach — підсистема зв’язку в ядрі XNU) і викликає `bsdthread_terminate` — syscall, який видаляє пов’язані з потоком структури на рівні ядра.

#### Механізми синхронізації

Для керування доступом до спільних ресурсів і запобігання race conditions macOS надає кілька примітивів синхронізації. Вони мають критичне значення в багатопотокових середовищах для забезпечення цілісності даних і стабільності системи:

1. **М’ютекси:**
- **Звичайний м’ютекс (сигнатура: 0x4D555458):** Стандартний м’ютекс із обсягом пам’яті 60 байтів (56 байтів для м’ютекса та 4 байти для сигнатури).
- **Швидкий м’ютекс (сигнатура: 0x4d55545A):** Подібний до звичайного м’ютекса, але оптимізований для швидшого виконання операцій; його розмір також становить 60 байтів.
2. **Змінні умов:**
- Використовуються для очікування настання певних умов; їхній розмір становить 44 байти (40 байтів плюс 4-байтна сигнатура).
- **Атрибути змінної умови (сигнатура: 0x434e4441):** Атрибути конфігурації змінних умов, розмір яких становить 12 байтів.
3. **Змінна Once (сигнатура: 0x4f4e4345):**
- Гарантує, що певний фрагмент коду ініціалізації буде виконано лише один раз. Її розмір становить 12 байтів.
4. **Блокування читання-запису:**
- Дозволяють одночасно працювати кільком читачам або одному записувачу, забезпечуючи ефективний доступ до спільних даних.
- **Блокування читання-запису (сигнатура: 0x52574c4b):** Розмір становить 196 байтів.
- **Атрибути блокування читання-запису (сигнатура: 0x52574c41):** Атрибути блокувань читання-запису, розмір яких становить 20 байтів.

> [!TIP]
> Останні 4 байти цих об’єктів використовуються для виявлення переповнень.

### Локальні змінні потоку (TLV)

**Локальні змінні потоку (TLV)** у контексті файлів Mach-O (формату виконуваних файлів у macOS) використовуються для оголошення змінних, специфічних для **кожного потоку** в багатопотоковій програмі. Це гарантує, що кожен потік матиме власний окремий екземпляр змінної, забезпечуючи спосіб уникнення конфліктів і підтримання цілісності даних без необхідності в явних механізмах синхронізації, таких як м’ютекси.

У C та споріднених мовах локальну змінну потоку можна оголосити за допомогою ключового слова **`__thread`**. Ось як це працює у вашому прикладі:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Цей фрагмент визначає `tlv_var` як thread-local змінну. Кожен thread, що виконує цей код, матиме власну `tlv_var`, і зміни, внесені одним thread до `tlv_var`, не впливатимуть на `tlv_var` в іншому thread.

У бінарному файлі Mach-O дані, пов'язані з thread-local змінними, організовані в окремі секції:

- **`__DATA.__thread_vars`**: ця секція містить метадані про thread-local змінні, як-от їхні типи та статус ініціалізації.
- **`__DATA.__thread_bss`**: ця секція використовується для thread-local змінних, які не були явно ініціалізовані. Це частина пам'яті, зарезервована для даних, ініціалізованих нулями.

Mach-O також надає спеціальний API **`tlv_atexit`** для керування thread-local змінними під час завершення thread. Цей API дає змогу **реєструвати деструктори** — спеціальні функції, які очищають thread-local дані, коли thread завершується.

### Пріоритети thread

Розуміння пріоритетів thread передбачає аналіз того, як операційна система вирішує, які thread запускати та коли це робити. На це впливає рівень пріоритету, призначений кожному thread. У macOS і Unix-подібних системах це реалізовано за допомогою таких концепцій, як `nice`, `renice` і класи Quality of Service (QoS).

#### Nice і Renice

1. **Nice:**
- Значення `nice` процесу — це число, яке впливає на його пріоритет. Кожен процес має значення nice від -20 (найвищий пріоритет) до 19 (найнижчий пріоритет). Типове значення nice під час створення процесу — 0.
- Нижче значення nice (ближче до -20) робить процес більш «егоїстичним», надаючи йому більше процесорного часу порівняно з іншими процесами з вищими значеннями nice.
2. **Renice:**
- `renice` — це команда для зміни значення nice вже запущеного процесу. Її можна використовувати для динамічного коригування пріоритету процесів, збільшуючи або зменшуючи виділення процесорного часу відповідно до нових значень nice.
- Наприклад, якщо процесу тимчасово потрібно більше процесорних ресурсів, його значення nice можна зменшити за допомогою `renice`.

#### Класи Quality of Service (QoS)

Класи QoS — це сучасніший підхід до керування пріоритетами thread, особливо в системах на кшталт macOS, які підтримують **Grand Central Dispatch (GCD)**. Класи QoS дають змогу розробникам **класифікувати** роботу за різними рівнями відповідно до її важливості або терміновості. macOS автоматично керує пріоритизацією thread на основі цих класів QoS:

1. **User Interactive:**
- Цей клас призначений для завдань, які безпосередньо взаємодіють із користувачем або потребують негайних результатів для забезпечення належного user experience. Таким завданням надається найвищий пріоритет, щоб інтерфейс залишався responsive (наприклад, анімації або обробка подій).
2. **User Initiated:**
- Завдання, ініційовані користувачем, для яких він очікує негайного результату, наприклад відкриття документа або натискання кнопки, що потребує обчислень. Вони мають високий пріоритет, але нижчий за User Interactive.
3. **Utility:**
- Це довготривалі завдання, які зазвичай відображають індикатор прогресу (наприклад, завантаження файлів або імпорт даних). Вони мають нижчий пріоритет, ніж User Initiated, і не повинні завершуватися негайно.
4. **Background:**
- Цей клас призначений для завдань, які працюють у background і невидимі для користувача. Це можуть бути індексація, синхронізація або backup. Вони мають найнижчий пріоритет і мінімально впливають на продуктивність системи.

Використовуючи класи QoS, розробникам не потрібно керувати точними числовими значеннями пріоритетів — достатньо зосередитися на характері завдання, а система відповідно оптимізує використання процесорних ресурсів.

Крім того, існують різні **політики планування thread**, які дають змогу визначити набір параметрів планування, що планувальник братиме до уваги. Це можна зробити за допомогою `thread_policy_[set/get]`. Такий підхід може бути корисним під час атак на race condition.

## macOS Process Abuse

macOS надає багато механізмів, за допомогою яких **процеси можуть взаємодіяти, обмінюватися даними та спільно використовувати їх**. Хоча ці механізми необхідні для нормальної роботи системи, attackers можуть зловживати ними для injection, code execution або доступу до даних.

### Library Injection

Library Injection — це техніка, за якої attacker **змушує процес завантажити malicious library**. Після injection бібліотека виконується в контексті цільового процесу, надаючи attacker ті самі дозволи та доступ, що й цьому процесу.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking передбачає **перехоплення викликів функцій** або повідомлень у програмному коді. За допомогою hooking attacker може **змінювати поведінку** процесу, спостерігати за чутливими даними або навіть отримувати контроль над потоком виконання.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) — це різні методи, за допомогою яких окремі процеси **обмінюються даними та спільно використовують їх**. Хоча IPC є фундаментальним для багатьох легітимних застосунків, його також можна використовувати для обходу ізоляції процесів, витоку чутливої інформації або виконання несанкціонованих дій.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications, запущені з певними env variables, можуть бути вразливими до process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Прапорці `--load-extension` і `--use-fake-ui-for-media-stream` можна використати для виконання **man in the browser attack**, що дає змогу викрадати натискання клавіш, traffic і cookies, inject scripts у pages тощо:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Файли NIB **визначають елементи user interface (UI)** та їхню взаємодію всередині застосунку. Однак вони можуть **виконувати довільні команди**, а **Gatekeeper не перешкоджає** повторному запуску вже виконаного застосунку, якщо **NIB file було змінено**. Тому їх можна використовувати, щоб змусити довільні програми виконувати довільні команди:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Можна inject JVM options через **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** або **`JDK_JAVA_OPTIONS`** і завантажити Java або native agent до запуску застосунку.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** попередньо завантажує attacker JavaScript через `--require` (file) або `--import data:text/javascript,…` (fileless, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** завантажує module в interactive REPL, а **`ELECTRON_RUN_AS_NODE`** повторно вмикає все це для Electron binaries.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Можна inject code у .NET applications через **`DOTNET_STARTUP_HOOKS`** до `Main` або зловживати debugging functionality .NET, якщо наявні необхідні prerequisites.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash читає **`BASH_ENV`**; interactive POSIX shells читають **`ENV`**; zsh читає **`$ZDOTDIR/.zshenv`**; а fish читає configuration нижче **`XDG_CONFIG_HOME`** або **`XDG_DATA_DIRS`**. Кожен із них може виконати контрольований startup file до запуску intended command. Bash також виконує command substitution, розміщену в **`PS4`**, щоразу, коли xtrace увімкнено (наприклад, через успадкований **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** або **`PHP_INI_SCAN_DIR`** можуть завантажити контрольовану PHP configuration, у якій **`auto_prepend_file`** виконується до target script.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Standalone Lua interpreter виконує code або `@file` зі змінної **`LUA_INIT`** (або її version-specific variant) до обробки target script.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** і **`R_PROFILE`** перенаправляють startup profiles, що містять R code. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** разом із R library path натомість можуть автоматично завантажити встановлений package.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** перенаправляє depot, у якому автоматично виконується `config/startup.jl`.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** або **`ERL_ZFLAGS`** можуть inject Erlang VM **`-eval`** expression без payload file; Elixir workloads зазвичай запускають ту саму VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** і **`OCTAVE_VERSION_INITFILE`** перенаправляють Octave startup scripts.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` — це cross-platform .NET app, тому кілька environment variables дають змогу виконати code до команди: **`XDG_CONFIG_HOME`** перенаправляє profile scripts, які запускаються під час startup, **`PSModulePath`** hijack-ає module auto-loading (розміщений `.psm1` виконується під час import і може shadow-ити built-in cmdlets), а .NET-змінні **`CORECLR_PROFILER`**/**`COR_PROFILER`** і **`DOTNET_STARTUP_HOOKS`** завантажують attacker code у process до `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Перевірте різні options, за допомогою яких Perl script може виконати довільний code у:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Також можна зловживати Ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**), щоб змусити довільні scripts виконувати довільний code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Стандартна-library chain **`PYTHONWARNINGS`** і **`BROWSER`** може виконати command під час parsing warning-filter. Альтернативний file-backed варіант розміщує `sitecustomize.py` у **`PYTHONPATH`**, щоб звичайна `site` initialization імпортувала його до target script. **`PYTHONBREAKPOINT`** запускає вибраний callable/module, коли code досягає `breakpoint()`. Variables, призначені лише для interactive режиму, як-от **`PYTHONSTARTUP`**, мають вужче застосування.

Зауважте, що executables, скомпільовані за допомогою **`pyinstaller`**, не використовують ці environmental variables, навіть якщо вони працюють із embedded python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (і його fallback **`EXINIT`**) під час normal startup виконується як Ex commands, тому `:!cmd` / `:call system(...)` забезпечують code execution, коли victim відкриває Vim/Neovim із контрольованим environment:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Окремо зазначимо, що Homebrew зазвичай встановлює Python у `/opt/homebrew`, де members локальної групи `admin` можуть мати змогу замінити launcher. Це writable-binary hijack, а не environment-variable injection; перш ніж вважати його exploitable, перевірте ownership і ACLs.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) — це open-source застосунок на основі **EndpointSecurity**, який виявляє та блокує process injection. Він є хорошим reference для сигналів, доступних через Endpoint Security, оскільки сповіщає про:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** під час exec процесу: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` і `ELECTRON_RUN_AS_NODE`.
- Виклики **`task_for_pid`** — один процес запитує task port іншого, що є prerequisite для injection у нього.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` і `--remote-debugging-port`, які запускають Electron app у debug mode та дають змогу будь-кому під'єднатися до неї й виконати code.<sup>[[3]](#references)</sup>
- **Створення symlink/hardlink між рівнями привілеїв** — класичний primitive «створити link як normal user і спрямувати його на privileged location». Зауважте, що **symlinks можна виявляти, але не блокувати**: EndpointSecurity не надає destination link до його створення.

### Calls made by other processes

У [**цьому blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) описано, як можна використовувати функцію **`task_name_for_pid`**, щоб отримати інформацію про інші **processes injecting code у process**, а потім отримати інформацію про цей інший process.<sup>[[4]](#references)</sup>

Зауважте, що для виклику цієї функції потрібно мати **той самий uid**, що й process, або бути **root** (і вона повертає інформацію про process, а не спосіб inject code).

## References

- [1] [Shield — виявлення process-injection у macOS з відкритим кодом (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew — чому Electron apps не можуть зберігати ваші secrets конфіденційно: опція --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight — виявлення task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
