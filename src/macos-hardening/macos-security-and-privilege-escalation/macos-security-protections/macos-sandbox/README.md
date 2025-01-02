# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MacOS Sandbox (спочатку називався Seatbelt) **обмежує програми**, що працюють всередині пісочниці, до **дозволених дій, зазначених у профілі Sandbox**, з яким працює програма. Це допомагає забезпечити, що **програма буде отримувати доступ лише до очікуваних ресурсів**.

Будь-яка програма з **правом** **`com.apple.security.app-sandbox`** буде виконуватися всередині пісочниці. **Бінарники Apple** зазвичай виконуються всередині пісочниці, і всі програми з **App Store мають це право**. Тому кілька програм буде виконуватися всередині пісочниці.

Щоб контролювати, що процес може або не може робити, **пісочниця має хуки** практично в будь-якій операції, яку процес може спробувати (включаючи більшість системних викликів) за допомогою **MACF**. Однак, **залежно** від **прав** програми, пісочниця може бути більш поблажливою до процесу.

Деякі важливі компоненти пісочниці:

- **Розширення ядра** `/System/Library/Extensions/Sandbox.kext`
- **Приватний фреймворк** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **Демон**, що працює в користувацькому просторі `/usr/libexec/sandboxd`
- **Контейнери** `~/Library/Containers`

### Containers

Кожна програма в пісочниці матиме свій власний контейнер у `~/Library/Containers/{CFBundleIdentifier}` :
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
У кожній папці з ідентифікатором пакета ви можете знайти **plist** та **каталог даних** програми зі структурою, що імітує домашню папку:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> Зверніть увагу, що навіть якщо символічні посилання існують для "втечі" з Sandbox і доступу до інших папок, додаток все ще повинен **мати дозволи** для їх доступу. Ці дозволи знаходяться в **`.plist`** у `RedirectablePaths`.

**`SandboxProfileData`** - це скомпільований профіль пісочниці CFData, закодований у B64.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> Все, що створюється/модифікується пісочницею, отримає **атрибут карантину**. Це запобіжить простору пісочниці, активуючи Gatekeeper, якщо пісочна програма намагається виконати щось за допомогою **`open`**.

## Профілі пісочниці

Профілі пісочниці - це конфігураційні файли, які вказують, що буде **дозволено/заборонено** в цій **пісочниці**. Вони використовують **Мову профілів пісочниці (SBPL)**, яка використовує [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) мову програмування.

Ось приклад:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> Перевірте це [**дослідження**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **щоб дізнатися більше про дії, які можуть бути дозволені або заборонені.**
>
> Зверніть увагу, що в скомпільованій версії профілю назви операцій замінюються їхніми записами в масиві, відомому dylib та kext, що робить скомпільовану версію коротшою і важчою для читання.

Важливі **системні сервіси** також працюють у своїх власних спеціальних **пісочницях**, таких як сервіс `mdnsresponder`. Ви можете переглянути ці спеціальні **профілі пісочниці** в:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Інші профілі пісочниці можна перевірити за посиланням [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Додатки з **App Store** використовують **профіль** **`/System/Library/Sandbox/Profiles/application.sb`**. Ви можете перевірити в цьому профілі, як права, такі як **`com.apple.security.network.server`**, дозволяють процесу використовувати мережу.

SIP - це профіль пісочниці, званий platform_profile в /System/Library/Sandbox/rootless.conf

### Приклади профілів пісочниці

Щоб запустити додаток з **конкретним профілем пісочниці**, ви можете використовувати:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!NOTE]
> Зверніть увагу, що **програмне забезпечення**, написане **Apple**, яке працює на **Windows**, **не має додаткових заходів безпеки**, таких як пісочниця для додатків.

Приклади обходів:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (вони можуть записувати файли поза пісочницею, назва яких починається з `~$`).

### Відстеження пісочниці

#### Через профіль

Можливо відстежувати всі перевірки, які виконує пісочниця щоразу, коли перевіряється дія. Для цього просто створіть наступний профіль:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
А потім просто виконайте щось, використовуючи цей профіль:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
У `/tmp/trace.out` ви зможете побачити кожну перевірку пісочниці, яка виконувалася щоразу, коли її викликали (тобто, багато дублікатів).

Також можливо відстежувати пісочницю, використовуючи параметр **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Через API

Функція `sandbox_set_trace_path`, експортована `libsystem_sandbox.dylib`, дозволяє вказати ім'я файлу трасування, куди будуть записані перевірки пісочниці.\
Також можливо зробити щось подібне, викликавши `sandbox_vtrace_enable()` і отримавши журнали помилок з буфера, викликавши `sandbox_vtrace_report()`.

### Інспекція пісочниці

`libsandbox.dylib` експортує функцію під назвою sandbox_inspect_pid, яка надає список стану пісочниці процесу (включаючи розширення). Однак лише платформи бінарних файлів можуть використовувати цю функцію.

### Профілі пісочниці MacOS та iOS

MacOS зберігає системні профілі пісочниці у двох місцях: **/usr/share/sandbox/** та **/System/Library/Sandbox/Profiles**.

І якщо сторонній додаток має право _**com.apple.security.app-sandbox**_, система застосовує профіль **/System/Library/Sandbox/Profiles/application.sb** до цього процесу.

В iOS за замовчуванням профіль називається **container**, і ми не маємо текстового представлення SBPL. У пам'яті ця пісочниця представлена як бінарне дерево Allow/Deny для кожного дозволу з пісочниці.

### Користувацький SBPL у додатках App Store

Можливо, що компанії можуть змусити свої додатки працювати **з користувацькими профілями пісочниці** (замість за замовчуванням). Вони повинні використовувати право **`com.apple.security.temporary-exception.sbpl`**, яке потрібно авторизувати в Apple.

Можна перевірити визначення цього права в **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Це **оцінить рядок після цього права** як профіль Sandbox.

### Компіляція та декомпіляція профілю Sandbox

Інструмент **`sandbox-exec`** використовує функції `sandbox_compile_*` з `libsandbox.dylib`. Основні експортовані функції: `sandbox_compile_file` (очікує шлях до файлу, параметр `-f`), `sandbox_compile_string` (очікує рядок, параметр `-p`), `sandbox_compile_name` (очікує назву контейнера, параметр `-n`), `sandbox_compile_entitlements` (очікує plist прав).

Ця реверсована та [**відкрита версія інструменту sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) дозволяє **`sandbox-exec`** записувати скомпільований профіль sandbox у файл.

Більше того, щоб обмежити процес всередині контейнера, він може викликати `sandbox_spawnattrs_set[container/profilename]` і передати контейнер або вже існуючий профіль.

## Налагодження та обхід Sandbox

На macOS, на відміну від iOS, де процеси з самого початку ізольовані ядром, **процеси повинні самостійно вибрати участь у sandbox**. Це означає, що на macOS процес не обмежується sandbox, поки він активно не вирішить увійти в нього, хоча програми з App Store завжди ізольовані.

Процеси автоматично ізолюються з userland, коли вони запускаються, якщо у них є право: `com.apple.security.app-sandbox`. Для детального пояснення цього процесу дивіться:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Розширення Sandbox**

Розширення дозволяють надати додаткові привілеї об'єкту і викликають одну з функцій:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Розширення зберігаються в другому слоті мітки MACF, доступному з облікових даних процесу. Наступний **`sbtool`** може отримати доступ до цієї інформації.

Зверніть увагу, що розширення зазвичай надаються дозволеними процесами, наприклад, `tccd` надасть токен розширення `com.apple.tcc.kTCCServicePhotos`, коли процес намагався отримати доступ до фотографій і був дозволений у повідомленні XPC. Тоді процесу потрібно буде спожити токен розширення, щоб він був доданий до нього.\
Зверніть увагу, що токени розширення є довгими шістнадцятковими числами, які кодують надані дозволи. Однак у них немає жорстко закодованого дозволеного PID, що означає, що будь-який процес з доступом до токена може бути **спожитий кількома процесами**.

Зверніть увагу, що розширення дуже пов'язані з правами, тому наявність певних прав може автоматично надавати певні розширення.

### **Перевірка привілеїв PID**

[**Згідно з цим**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), функції **`sandbox_check`** (це `__mac_syscall`), можуть перевірити **чи дозволена операція чи ні** sandbox у певному PID, аудиторському токені або унікальному ID.

[**Інструмент sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (знайдіть його [скомпільованим тут](https://newosxbook.com/articles/hitsb.html)) може перевірити, чи може PID виконати певні дії:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Також можливо призупинити та відновити пісочницю, використовуючи функції `sandbox_suspend` та `sandbox_unsuspend` з `libsystem_sandbox.dylib`.

Зверніть увагу, що для виклику функції призупинення перевіряються деякі права для авторизації виклику, такі як:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Цей системний виклик (#381) очікує один рядок як перший аргумент, який вказуватиме модуль для виконання, а потім код у другому аргументі, який вказуватиме функцію для виконання. Третій аргумент залежатиме від виконуваної функції.

Виклик функції `___sandbox_ms` обгортає `mac_syscall`, вказуючи в першому аргументі `"Sandbox"`, так само як `___sandbox_msp` є обгорткою для `mac_set_proc` (#387). Деякі з підтримуваних кодів `___sandbox_ms` можна знайти в цій таблиці:

- **set_profile (#0)**: Застосувати скомпільований або іменований профіль до процесу.
- **platform_policy (#1)**: Застосувати перевірки політики, специфічні для платформи (варіюється між macOS та iOS).
- **check_sandbox (#2)**: Виконати ручну перевірку конкретної операції пісочниці.
- **note (#3)**: Додати анотацію до пісочниці.
- **container (#4)**: Прикріпити анотацію до пісочниці, зазвичай для налагодження або ідентифікації.
- **extension_issue (#5)**: Створити нове розширення для процесу.
- **extension_consume (#6)**: Використати дане розширення.
- **extension_release (#7)**: Вивільнити пам'ять, пов'язану з використаним розширенням.
- **extension_update_file (#8)**: Змінити параметри існуючого розширення файлу в межах пісочниці.
- **extension_twiddle (#9)**: Налаштувати або змінити існуюче розширення файлу (наприклад, TextEdit, rtf, rtfd).
- **suspend (#10)**: Тимчасово призупинити всі перевірки пісочниці (вимагає відповідних прав).
- **unsuspend (#11)**: Відновити всі раніше призупинені перевірки пісочниці.
- **passthrough_access (#12)**: Дозволити прямий доступ до ресурсу, обходячи перевірки пісочниці.
- **set_container_path (#13)**: (тільки iOS) Встановити шлях контейнера для групи додатків або ID підпису.
- **container_map (#14)**: (тільки iOS) Отримати шлях контейнера з `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Встановити метадані режиму користувача в пісочниці.
- **inspect (#16)**: Надати інформацію для налагодження про процес, що працює в пісочниці.
- **dump (#18)**: (macOS 11) Вивантажити поточний профіль пісочниці для аналізу.
- **vtrace (#19)**: Відстежувати операції пісочниці для моніторингу або налагодження.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Деактивувати іменовані профілі (наприклад, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Виконати кілька операцій `sandbox_check` в одному виклику.
- **reference_retain_by_audit_token (#28)**: Створити посилання для аудиторського токена для використання в перевірках пісочниці.
- **reference_release (#29)**: Вивільнити раніше збережене посилання на аудиторський токен.
- **rootless_allows_task_for_pid (#30)**: Перевірити, чи дозволено `task_for_pid` (схоже на перевірки `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Застосувати файл маніфесту системної цілісності (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Перевірити файл маніфесту SIP перед виконанням.
- **rootless_protected_volume (#33)**: (macOS) Застосувати SIP-захисти до диска або розділу.
- **rootless_mkdir_protected (#34)**: Застосувати SIP/DataVault захист до процесу створення каталогу.

## Sandbox.kext

Зверніть увагу, що в iOS розширення ядра містить **жорстко закодовані всі профілі** всередині сегмента `__TEXT.__const`, щоб уникнути їх модифікації. Ось деякі цікаві функції з розширення ядра:

- **`hook_policy_init`**: Він підключає `mpo_policy_init` і викликається після `mac_policy_register`. Він виконує більшість ініціалізацій пісочниці. Він також ініціалізує SIP.
- **`hook_policy_initbsd`**: Налаштовує інтерфейс sysctl, реєструючи `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` та `security.mac.sandbox.debug_mode` (якщо завантажено з `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Викликається `mac_syscall` з "Sandbox" як першим аргументом і кодом, що вказує на операцію, у другому. Використовується оператор switch для знаходження коду для виконання відповідно до запитуваного коду.

### MACF Hooks

**`Sandbox.kext`** використовує більше ста хуків через MACF. Більшість хуків просто перевіряють деякі тривіальні випадки, які дозволяють виконати дію, якщо ні, вони викликають **`cred_sb_evalutate`** з **обліковими даними** з MACF та номером, що відповідає **операції**, яку потрібно виконати, і **буфером** для виходу.

Добрим прикладом цього є функція **`_mpo_file_check_mmap`**, яка підключає **`mmap`** і яка почне перевіряти, чи буде нова пам'ять записуваною (і якщо ні, дозволить виконання), потім перевірить, чи використовується вона для спільного кешу dyld, і якщо так, дозволить виконання, а в кінці викличе **`sb_evaluate_internal`** (або одну з його обгорток) для виконання подальших перевірок дозволу.

Більше того, з сотень хуків, які використовує пісочниця, є 3, які особливо цікаві:

- `mpo_proc_check_for`: Застосовує профіль, якщо це необхідно, і якщо він не був раніше застосований.
- `mpo_vnode_check_exec`: Викликається, коли процес завантажує асоційований бінарний файл, тоді виконується перевірка профілю, а також перевірка, що забороняє виконання SUID/SGID.
- `mpo_cred_label_update_execve`: Це викликається, коли призначається мітка. Це найдовший, оскільки викликається, коли бінарний файл повністю завантажений, але ще не виконаний. Він виконує такі дії, як створення об'єкта пісочниці, прикріплення структури пісочниці до облікових даних kauth, видалення доступу до mach портів...

Зверніть увагу, що **`_cred_sb_evalutate`** є обгорткою над **`sb_evaluate_internal`**, і ця функція отримує передані облікові дані, а потім виконує оцінку, використовуючи функцію **`eval`**, яка зазвичай оцінює **профіль платформи**, який за замовчуванням застосовується до всіх процесів, а потім **специфічний профіль процесу**. Зверніть увагу, що профіль платформи є одним з основних компонентів **SIP** в macOS.

## Sandboxd

Пісочниця також має демон користувача, який запускає XPC Mach сервіс `com.apple.sandboxd` і прив'язує спеціальний порт 14 (`HOST_SEATBELT_PORT`), який розширення ядра використовує для зв'язку з ним. Він надає деякі функції, використовуючи MIG.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
