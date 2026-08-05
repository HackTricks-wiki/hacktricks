# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

MacOS Sandbox (спочатку називався Seatbelt) **обмежує застосунки**, що працюють усередині sandbox, до **дозволених дій, указаних у профілі Sandbox**, з яким працює застосунок. Це допомагає гарантувати, що **застосунок матиме доступ лише до очікуваних ресурсів**.

Будь-який застосунок із **entitlement** **`com.apple.security.app-sandbox`** виконуватиметься всередині sandbox. **Бінарні файли Apple** зазвичай виконуються всередині Sandbox, а всі застосунки з **App Store мають цей entitlement**. Отже, кілька застосунків виконуватимуться всередині sandbox.<sup>[4]</sup>

Щоб контролювати, що процес може або не може робити, **Sandbox має hooks** майже в кожній операції, яку може спробувати виконати процес (зокрема у більшості syscall), використовуючи **MACF**. Однак, з**алежно** від **entitlements** застосунку Sandbox може бути прихильнішим до процесу.

Деякі важливі компоненти Sandbox:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **daemon**, що працює в userland `/usr/libexec/sandboxd`
- **контейнери** `~/Library/Containers`

### Контейнери

Кожен sandboxed застосунок матиме власний контейнер у `~/Library/Containers/{CFBundleIdentifier}` :
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
Усередині кожної папки bundle id можна знайти **plist** і **Data directory** App зі структурою, що імітує Home folder:
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
> Зверніть увагу, що навіть якщо symlinks присутні, щоб «вийти» із Sandbox і отримати доступ до інших папок, App все одно має **мати дозволи** на доступ до них. Ці дозволи містяться у **`.plist`** в `RedirectablePaths`.

**`SandboxProfileData`** — це скомпільований профіль Sandbox у форматі CFData, закодований у B64.
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
> Усе, що створює або змінює застосунок у Sandbox, отримує **атрибут карантину**. Це запобігає використанню простору Sandbox, активуючи Gatekeeper, якщо застосунок у Sandbox намагається виконати щось за допомогою **`open`**.

## Профілі Sandbox

Профілі Sandbox — це конфігураційні файли, які визначають, що буде **дозволено/заборонено** в цьому **Sandbox**. Вони використовують **Sandbox Profile Language (SBPL)**, яка базується на мові програмування [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Тут наведено приклад:
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
> Перегляньте це [**дослідження**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/), щоб перевірити інші дії, які можуть бути дозволені або заборонені.<sup>[5]</sup>
>
> Зверніть увагу, що у скомпільованій версії профілю назви операцій замінюються їхніми записами в масиві, відомому dylib і kext, завдяки чому скомпільована версія стає коротшою та складнішою для читання.

Важливі **системні служби** також працюють у власному спеціальному **sandbox**, наприклад служба `mdnsresponder`. Переглянути ці спеціальні **sandbox profiles** можна тут:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Інші sandbox profiles можна переглянути тут: [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- В iOS platform profile розташований усередині sandbox `.kext`, у `_platform_profile_data` всередині binary.

Програми **App Store** використовують **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. У цьому профілі можна перевірити, як entitlements, такі як **`com.apple.security.network.server`**, дозволяють процесу використовувати мережу.

Деякі **Apple daemon services** використовують інші profiles, розташовані в `/System/Library/Sandbox/Profiles/*.sb` або `/usr/share/sandbox/*.sb`. Ці sandboxes застосовуються в основній функції, яка викликає API `sandbox_init_XXX`.<sup>[3]</sup>

**SIP** — це Sandbox profile під назвою platform_profile у `/System/Library/Sandbox/rootless.conf`.

### Приклади Sandbox Profile

Щоб запустити програму з **певним sandbox profile**, можна використати:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
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

> [!TIP]
> Зверніть увагу, що **software** авторства **Apple**, яке працює у **Windows**, **не має додаткових заходів безпеки**, таких як application sandboxing.

Приклади bypass:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[6]</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (їм вдається записувати файли за межами sandbox, назви яких починаються з `~$`).<sup>[7]</sup>

### Трасування Sandbox

#### Через profile

Можна відстежувати всі перевірки, які виконує sandbox щоразу під час перевірки дії. Для цього просто створіть такий profile:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
А потім просто виконайте щось, використовуючи цей профіль:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
У `/tmp/trace.out` можна побачити кожну перевірку Sandbox щоразу, коли її було виконано (тому там багато дублікатів).

Також Sandbox можна трасувати за допомогою параметра **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Через API

Функція `sandbox_set_trace_path`, експортована `libsystem_sandbox.dylib`, дозволяє вказати назву файлу trace, у який записуватимуться перевірки Sandbox.\
Також можна зробити щось подібне, викликавши `sandbox_vtrace_enable()`, а потім отримати помилки з буфера за допомогою `sandbox_vtrace_report()`.

### Інспекція Sandbox

`libsandbox.dylib` експортує функцію під назвою sandbox_inspect_pid, яка надає список стану Sandbox процесу (включно з extensions). Однак використовувати цю функцію можуть лише platform binaries.

### Профілі Sandbox у MacOS та iOS

MacOS зберігає системні профілі Sandbox у двох місцях: **/usr/share/sandbox/** та **/System/Library/Sandbox/Profiles**.

Якщо сторонній застосунок має entitlement _**com.apple.security.app-sandbox**_, система застосовує до цього процесу профіль **/System/Library/Sandbox/Profiles/application.sb**.

В iOS профіль за замовчуванням називається **container**, і ми не маємо його текстового представлення SBPL. У пам’яті цей Sandbox представлений як бінарне дерево Allow/Deny для кожного дозволу Sandbox.

### Custom SBPL у застосунках App Store

Компанії можуть запускати свої застосунки **з custom Sandbox profiles** (замість профілю за замовчуванням). Для цього їм потрібно використовувати entitlement **`com.apple.security.temporary-exception.sbpl`**, який має бути авторизований Apple.

Визначення цього entitlement можна переглянути в **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Це **eval рядок після цього entitlement** як Sandbox profile.

### Компіляція та декомпіляція Sandbox Profile

Інструмент **`sandbox-exec`** використовує функції `sandbox_compile_*` з `libsandbox.dylib`. Основні експортовані функції: `sandbox_compile_file` (очікує шлях до файлу, параметр `-f`), `sandbox_compile_string` (очікує рядок, параметр `-p`), `sandbox_compile_name` (очікує назву контейнера, параметр `-n`), `sandbox_compile_entitlements` (очікує entitlements plist).

Ця реверснута та [**open sourced версія інструмента sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) дозволяє змусити **`sandbox-exec`** записати скомпільований Sandbox profile у файл.

Крім того, щоб обмежити процес усередині контейнера, він може викликати `sandbox_spawnattrs_set[container/profilename]` і передати контейнер або попередньо створений profile.

## Debug та обхід Sandbox

У macOS, на відміну від iOS, де процеси sandboxed з самого початку kernel, **процеси повинні самостійно opt-in до Sandbox**. Це означає, що в macOS процес не обмежується Sandbox, доки сам активно не вирішить увійти до нього, хоча App Store apps завжди sandboxed.

Процеси автоматично Sandbox-яться з userland під час запуску, якщо вони мають entitlement: `com.apple.security.app-sandbox`. Для детального пояснення цього процесу перегляньте:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions дозволяють надати додаткові privileges об’єкту та надаються через виклик однієї з функцій:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions зберігаються у другому слоті MACF label, доступному з credentials процесу. Наведений нижче **`sbtool`** може отримати доступ до цієї інформації.

Зверніть увагу, що extensions зазвичай надаються дозволеними процесами; наприклад, `tccd` надасть extension token `com.apple.tcc.kTCCServicePhotos`, коли процес спробує отримати доступ до photos і йому буде дозволено це через XPC message. Після цього процесу потрібно використати extension token, щоб його було додано до процесу.\
Зверніть увагу, що extension tokens — це довгі hexadecimals, які кодують надані permissions. Однак вони не містять hardcoded allowed PID, що означає: будь-який процес, який має доступ до token, може бути **consumed кількома процесами**.

Зверніть увагу, що extensions також тісно пов’язані з entitlements, тому наявність певних entitlements може автоматично надавати певні extensions.

### **Перевірка Privileges PID**

[**Згідно з цим**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), функції **`sandbox_check`** (це `__mac_syscall`) можуть перевірити, **чи дозволена операція Sandbox чи ні** для певного PID, audit token або unique ID.<sup>[8]</sup>

Інструмент [**sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (знайти його [скомпільованим тут](https://newosxbook.com/articles/hitsb.html)) може перевірити, чи може PID виконувати певні дії:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Також можна призупинити та відновити Sandbox за допомогою функцій `sandbox_suspend` і `sandbox_unsuspend` з `libsystem_sandbox.dylib`.

Зверніть увагу, що для виклику функції призупинення перевіряються певні entitlements, щоб авторизувати caller для її виклику:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Цей системний виклик (#381) очікує перший аргумент у вигляді рядка, який вказує модуль для запуску, а потім код у другому аргументі, який вказує функцію для запуску. Третій аргумент залежатиме від виконуваної функції.<sup>[2]</sup>

Функція `___sandbox_ms` обгортає виклик `mac_syscall`, вказуючи в першому аргументі `"Sandbox"`, так само як `___sandbox_msp` є wrapper для `mac_set_proc` (#387). Деякі підтримувані `___sandbox_ms` коди наведені в цій таблиці:

- **set_profile (#0)**: Застосувати скомпільований або іменований профіль до процесу.
- **platform_policy (#1)**: Застосувати перевірки політики, специфічні для платформи (відрізняються між macOS та iOS).
- **check_sandbox (#2)**: Виконати ручну перевірку певної операції Sandbox.
- **note (#3)**: Додати нотацію до Sandbox.
- **container (#4)**: Додати анотацію до Sandbox, зазвичай для debugging або ідентифікації.
- **extension_issue (#5)**: Створити нове extension для процесу.
- **extension_consume (#6)**: Використати надане extension.
- **extension_release (#7)**: Звільнити пам'ять, пов'язану з використаним extension.
- **extension_update_file (#8)**: Змінити параметри наявного file extension у Sandbox.
- **extension_twiddle (#9)**: Налаштувати або змінити наявне file extension (наприклад, TextEdit, rtf, rtfd).
- **suspend (#10)**: Тимчасово призупинити всі перевірки Sandbox (потребує відповідних entitlements).
- **unsuspend (#11)**: Відновити всі раніше призупинені перевірки Sandbox.
- **passthrough_access (#12)**: Дозволити прямий passthrough-доступ до ресурсу, обходячи перевірки Sandbox.
- **set_container_path (#13)**: (лише iOS) Встановити шлях до container для app group або signing ID.
- **container_map (#14)**: (лише iOS) Отримати шлях до container від `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Встановити метадані user mode у Sandbox.
- **inspect (#16)**: Надати debugging-інформацію про процес у Sandbox.
- **dump (#18)**: (macOS 11) Вивантажити поточний профіль Sandbox для аналізу.
- **vtrace (#19)**: Трасувати операції Sandbox для моніторингу або debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Деактивувати іменовані профілі (наприклад, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Виконати кілька операцій `sandbox_check` за один виклик.
- **reference_retain_by_audit_token (#28)**: Створити reference для audit token, щоб використовувати його в перевірках Sandbox.
- **reference_release (#29)**: Звільнити раніше збережений reference на audit token.
- **rootless_allows_task_for_pid (#30)**: Перевірити, чи дозволено `task_for_pid` (аналогічно до перевірок `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Застосувати файл маніфесту System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Перевірити файл маніфесту SIP перед виконанням.
- **rootless_protected_volume (#33)**: (macOS) Застосувати захист SIP до диска або розділу.
- **rootless_mkdir_protected (#34)**: Застосувати захист SIP/DataVault до процесу створення директорії.

## Sandbox.kext

Зверніть увагу, що в iOS kernel extension містить **hardcoded усі профілі** всередині сегмента `__TEXT.__const`, щоб запобігти їх зміні. Нижче наведено деякі цікаві функції kernel extension:

- **`hook_policy_init`**: Перехоплює `mpo_policy_init` і викликається після `mac_policy_register`. Виконує більшість ініціалізацій Sandbox. Також ініціалізує SIP.
- **`hook_policy_initbsd`**: Налаштовує інтерфейс sysctl, реєструючи `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` і `security.mac.sandbox.debug_mode` (якщо завантажено з `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Викликається `mac_syscall` з `"Sandbox"` як першим аргументом і кодом, що вказує операцію, як другим. Для пошуку коду, який потрібно виконати відповідно до запитаного коду, використовується switch.

### MACF Hooks

**`Sandbox.kext`** використовує понад сотню hooks через MACF. Більшість hooks лише перевіряють деякі тривіальні випадки, які дозволяють виконати дію; якщо ні, вони викликають **`cred_sb_evalutate`** з **credentials** від MACF, числом, що відповідає **operation**, яку потрібно виконати, і **buffer** для результату.<sup>[1]</sup>

Хорошим прикладом є функція **`_mpo_file_check_mmap`**, яка hook-ить `mmap`. Вона спочатку перевіряє, чи буде нова пам'ять доступною для запису (і, якщо ні, дозволяє виконання), потім перевіряє, чи використовується вона для dyld shared cache, і, якщо так, дозволяє виконання, а врешті викликає **`sb_evaluate_internal`** (або один із його wrappers) для виконання подальших перевірок дозволу.

Крім сотень hooks, які використовує Sandbox, є 3 особливо цікаві:

- `mpo_proc_check_for`: Застосовує профіль, якщо це необхідно і якщо його ще не було застосовано.
- `mpo_vnode_check_exec`: Викликається, коли процес завантажує пов'язаний binary; після цього виконується перевірка профілю, а також перевірка, що забороняє виконання SUID/SGID.
- `mpo_cred_label_update_execve`: Викликається, коли label призначається. Це найдовша функція, оскільки вона викликається, коли binary повністю завантажено, але ще не виконано. Вона виконує такі дії, як створення Sandbox object, приєднання структури Sandbox до kauth credentials, видалення доступу до mach ports тощо.

Зверніть увагу, що **`_cred_sb_evalutate`** є wrapper над **`sb_evaluate_internal`**. Ця функція отримує передані credentials, а потім виконує evaluation за допомогою функції **`eval`**, яка зазвичай оцінює **platform profile**, що за замовчуванням застосовується до всіх процесів, а потім **specific process profile**. Зверніть увагу, що platform profile є одним із головних компонентів **SIP** у macOS.

## Sandboxd

Sandbox також має user daemon, який працює та відкриває XPC Mach service `com.apple.sandboxd`, прив'язуючи special port 14 (`HOST_SEATBELT_PORT`), який kernel extension використовує для взаємодії з ним. Він відкриває деякі функції за допомогою MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
