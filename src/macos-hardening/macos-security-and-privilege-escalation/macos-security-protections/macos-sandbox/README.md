# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

MacOS Sandbox (спочатку називався Seatbelt) **обмежує застосунки**, що працюють усередині sandbox, до **дозволених дій, зазначених у профілі Sandbox**, з яким працює застосунок. Це допомагає гарантувати, що **застосунок отримуватиме доступ лише до очікуваних ресурсів**.

Будь-який застосунок із **entitlement** **`com.apple.security.app-sandbox`** виконуватиметься всередині sandbox. **Бінарні файли Apple** зазвичай виконуються всередині Sandbox, а всі застосунки з **App Store мають цей entitlement**. Отже, кілька застосунків виконуватимуться всередині sandbox.<sup>[[4]](#references)</sup>

Щоб контролювати, що процес може або не може робити, **Sandbox має hooks** майже в кожній операції, яку може спробувати виконати процес (зокрема у більшості syscalls), використовуючи **MACF**. Однак, **залежно** від **entitlements** застосунку Sandbox може надавати процесу більше дозволів.

Деякі важливі компоненти Sandbox:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **daemon**, що працює в userland: `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Контейнери

Кожен застосунок, що працює в sandbox, матиме власний container у `~/Library/Containers/{CFBundleIdentifier}` :
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
Усередині папки кожного **bundle id** можна знайти **plist** і **Data directory** програми зі структурою, що імітує домашню папку:
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
> Зверніть увагу, що навіть якщо symlinks існують, щоб «вийти» із Sandbox і отримати доступ до інших папок, App усе одно має **мати дозволи** на доступ до них. Ці дозволи містяться у **`.plist`** в `RedirectablePaths`.

**`SandboxProfileData`** — це скомпільований профіль Sandbox у форматі CFData, екранований у B64.
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
> Усе, що створює або змінює застосунок у Sandbox, отримає **атрибут quarantine**. Це запобігатиме використанню простору Sandbox, активуючи Gatekeeper, якщо застосунок у Sandbox спробує виконати щось за допомогою **`open`**.

## Профілі Sandbox

Профілі Sandbox — це конфігураційні файли, які визначають, що буде **дозволено/заборонено** в цьому **Sandbox**. Вони використовують **мову профілів Sandbox (SBPL)**, яка базується на мові програмування [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Тут ви можете знайти приклад:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

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
> Перегляньте це [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/), щоб дізнатися про інші дії, які можуть бути дозволені або заборонені.<sup>[[5]](#references)</sup>
>
> Зверніть увагу, що в скомпільованій версії профілю назви операцій замінюються їхніми записами в масиві, відомому dylib і kext, завдяки чому скомпільована версія стає коротшою та складнішою для читання.

Важливі **системні служби** також працюють у власному спеціальному **sandbox**, наприклад служба `mdnsresponder`. Ви можете переглянути ці спеціальні **профілі sandbox** у таких місцях:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Інші профілі sandbox можна переглянути за посиланням [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- В iOS профіль платформи розташований усередині `.kext` sandbox, у `_platform_profile_data` всередині бінарного файла.

Програми **App Store** використовують **профіль** **`/System/Library/Sandbox/Profiles/application.sb`**. У цьому профілі можна перевірити, як entitlements, такі як **`com.apple.security.network.server`**, дозволяють процесу використовувати мережу.

Далі, деякі **демони Apple** використовують різні профілі, розташовані в `/System/Library/Sandbox/Profiles/*.sb` або `/usr/share/sandbox/*.sb`. Ці sandbox застосовуються в головній функції, яка викликає API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

**SIP** — це профіль Sandbox під назвою platform_profile у `/System/Library/Sandbox/rootless.conf`.

### Приклади профілів Sandbox

Щоб запустити програму з **певним профілем sandbox**, можна використати:
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
> Зверніть увагу, що **програмне забезпечення**, створене **Apple** і призначене для роботи у **Windows**, **не має додаткових заходів безпеки**, таких як application sandboxing.

Приклади обходу:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (їм вдалося записувати файли за межами sandbox, назва яких починається з `~$`).<sup>[[7]](#references)</sup>

### Трасування Sandbox

#### За допомогою профілю

Можна відстежувати всі перевірки, які виконує sandbox щоразу, коли перевіряється дія. Для цього просто створіть такий профіль:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
А потім просто виконайте щось, використовуючи цей профіль:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
У `/tmp/trace.out` можна побачити кожну перевірку sandbox, виконану щоразу під час її виклику (тому там багато дублікатів).

Також sandbox можна трасувати за допомогою параметра **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Через API

Функція `sandbox_set_trace_path`, експортована `libsystem_sandbox.dylib`, дає змогу вказати ім’я файлу трасування, до якого записуватимуться перевірки sandbox.\
Також можна зробити щось подібне, викликавши `sandbox_vtrace_enable()`, а потім отримати помилки журналу з буфера за допомогою `sandbox_vtrace_report()`.

### Перевірка Sandbox

`libsandbox.dylib` експортує функцію sandbox_inspect_pid, яка повертає список станів sandbox процесу (включно з extensions). Однак використовувати цю функцію можуть лише platform binaries.

### Профілі Sandbox macOS та iOS

macOS зберігає системні профілі sandbox у двох розташуваннях: **/usr/share/sandbox/** та **/System/Library/Sandbox/Profiles**.

Якщо сторонній застосунок має entitlement _**com.apple.security.app-sandbox**_, система застосовує до цього процесу профіль **/System/Library/Sandbox/Profiles/application.sb**.

В iOS профіль за замовчуванням називається **container**, і ми не маємо його текстового представлення SBPL. У пам’яті цей sandbox представлений як бінарне дерево Allow/Deny для кожного дозволу sandbox.

### Власний SBPL у застосунках App Store

Компанії можуть запускати свої застосунки **з власними профілями Sandbox** (замість профілю за замовчуванням). Для цього їм потрібно використовувати entitlement **`com.apple.security.temporary-exception.sbpl`**, який має бути схвалений Apple.

Визначення цього entitlement можна перевірити у **`/System/Library/Sandbox/Profiles/application.sb:`**
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

Ця реверснута й [**open sourced версія інструмента sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) дає змогу змусити **`sandbox-exec`** записати скомпільований Sandbox profile у файл.

Крім того, щоб обмежити процес у контейнері, він може викликати `sandbox_spawnattrs_set[container/profilename]` і передати контейнер або попередньо створений profile.

## Debug і обхід Sandbox

У macOS, на відміну від iOS, де процеси sandboxed ядром із самого початку, **процеси повинні самостійно opt-in до Sandbox**. Це означає, що в macOS процес не обмежується Sandbox, доки активно не вирішить увійти до нього, хоча застосунки з App Store завжди sandboxed.

Процеси автоматично Sandbox-уються з userland під час запуску, якщо мають entitlement: `com.apple.security.app-sandbox`. Докладне пояснення цього процесу наведено тут:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions дають змогу надати об’єкту додаткові привілеї та викликають одну з таких функцій:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions зберігаються у другому слоті мітки MACF, доступному з credentials процесу. Наведений нижче **`sbtool`** може отримати доступ до цієї інформації.

Зверніть увагу, що extensions зазвичай надаються дозволеними процесами. Наприклад, `tccd` надасть extension token `com.apple.tcc.kTCCServicePhotos`, коли процес спробує отримати доступ до фотографій, і доступ буде дозволено в XPC message. Після цього процесу потрібно спожити extension token, щоб його було додано до процесу.\
Зверніть увагу, що extension tokens — це довгі hexadecimal значення, які кодують надані дозволи. Однак вони не містять жорстко заданого дозволеного PID, а це означає, що будь-який процес із доступом до token може бути **consumed кількома процесами**.

Зверніть увагу, що extensions також тісно пов’язані з entitlements, тому наявність певних entitlements може автоматично надавати певні extensions.

### **Перевірка привілеїв PID**

[**Відповідно до цього**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), функції **`sandbox_check`** (це `__mac_syscall`) можуть перевіряти, **чи дозволена певна операція Sandbox чи ні** для певного PID, audit token або унікального ID.<sup>[[8]](#references)</sup>

Інструмент [**sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (його скомпільовану версію можна знайти [тут](https://newosxbook.com/articles/hitsb.html)) може перевірити, чи здатен PID виконувати певні дії:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Також можна призупинити та відновити sandbox за допомогою функцій `sandbox_suspend` і `sandbox_unsuspend` з `libsystem_sandbox.dylib`.

Зверніть увагу, що для виклику функції призупинення перевіряються деякі entitlements, щоб авторизувати caller для її виклику, зокрема:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Цей системний виклик (#381) очікує один рядковий перший аргумент, який вказує модуль для запуску, а потім код у другому аргументі, який вказує функцію для запуску. Третій аргумент залежатиме від виконаної функції.<sup>[[2]](#references)</sup>

Функція `___sandbox_ms` є wrapper-ом для `mac_syscall`, який передає в першому аргументі `"Sandbox"`, так само як `___sandbox_msp` є wrapper-ом для `mac_set_proc` (#387). Деякі підтримувані `___sandbox_ms` коди наведено в цій таблиці:

- **set_profile (#0)**: Застосувати скомпільований або іменований profile до процесу.
- **platform_policy (#1)**: Застосувати platform-specific policy checks (відрізняються між macOS та iOS).
- **check_sandbox (#2)**: Виконати manual check певної sandbox operation.
- **note (#3)**: Додати annotation до Sandbox.
- **container (#4)**: Приєднати annotation до sandbox, зазвичай для debugging або identification.
- **extension_issue (#5)**: Згенерувати нове extension для процесу.
- **extension_consume (#6)**: Використати надане extension.
- **extension_release (#7)**: Звільнити пам’ять, пов’язану з використаним extension.
- **extension_update_file (#8)**: Змінити параметри наявного file extension у sandbox.
- **extension_twiddle (#9)**: Налаштувати або змінити наявне file extension (наприклад, TextEdit, rtf, rtfd).
- **suspend (#10)**: Тимчасово призупинити всі sandbox checks (потребує відповідних entitlements).
- **unsuspend (#11)**: Відновити всі раніше призупинені sandbox checks.
- **passthrough_access (#12)**: Дозволити direct passthrough access до resource, обходячи sandbox checks.
- **set_container_path (#13)**: (лише iOS) Встановити container path для app group або signing ID.
- **container_map (#14)**: (лише iOS) Отримати container path від `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Встановити user mode metadata у sandbox.
- **inspect (#16)**: Надати debug information про sandboxed process.
- **dump (#18)**: (macOS 11) Вивести поточний profile sandbox для analysis.
- **vtrace (#19)**: Відстежувати sandbox operations для monitoring або debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Деактивувати named profiles (наприклад, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Виконати кілька `sandbox_check` operations за один виклик.
- **reference_retain_by_audit_token (#28)**: Створити reference для audit token для використання в sandbox checks.
- **reference_release (#29)**: Звільнити раніше збережений audit token reference.
- **rootless_allows_task_for_pid (#30)**: Перевірити, чи дозволено `task_for_pid` (аналогічно до `csr` checks).
- **rootless_whitelist_push (#31)**: (macOS) Застосувати System Integrity Protection (SIP) manifest file.
- **rootless_whitelist_check (preflight) (#32)**: Перевірити SIP manifest file перед виконанням.
- **rootless_protected_volume (#33)**: (macOS) Застосувати SIP protections до disk або partition.
- **rootless_mkdir_protected (#34)**: Застосувати SIP/DataVault protection до процесу створення directory.

## Sandbox.kext

Зверніть увагу, що в iOS kernel extension містить **hardcoded усі profiles** у сегменті `__TEXT.__const`, щоб запобігти їх зміні. Нижче наведено деякі цікаві функції kernel extension:

- **`hook_policy_init`**: Перехоплює `mpo_policy_init` і викликається після `mac_policy_register`. Виконує більшість initializations Sandbox. Також ініціалізує SIP.
- **`hook_policy_initbsd`**: Налаштовує sysctl interface, реєструючи `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` і `security.mac.sandbox.debug_mode` (якщо завантажено з `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Викликається `mac_syscall` з `"Sandbox"` як першим аргументом і кодом, що вказує operation, як другим. Для пошуку коду, який потрібно виконати відповідно до requested code, використовується switch.

### MACF Hooks

**`Sandbox.kext`** використовує понад сотню hooks через MACF. Більшість hooks лише перевіряють деякі trivial cases, які дозволяють виконати action; якщо ні, вони викликають **`cred_sb_evalutate`** з **credentials** від MACF, числом, що відповідає **operation**, яку потрібно виконати, і **buffer** для output.<sup>[[1]](#references)</sup>

Хорошим прикладом є функція **`_mpo_file_check_mmap`**, яка hooked для **`mmap`** і спочатку перевіряє, чи буде нова memory writable (і якщо ні, дозволяє execution), потім перевіряє, чи використовується вона для dyld shared cache, і якщо так, дозволяє execution, а зрештою викликає **`sb_evaluate_internal`** (або один із його wrappers) для виконання подальших allowance checks.

Крім сотень hooks, які використовує Sandbox, особливо цікавими є 3:

- `mpo_proc_check_for`: Застосовує profile, якщо це потрібно і якщо його ще не було застосовано.
- `mpo_vnode_check_exec`: Викликається, коли process завантажує пов’язаний binary; після цього виконується profile check, а також check, що забороняє SUID/SGID executions.
- `mpo_cred_label_update_execve`: Викликається, коли label призначається. Це найдовша функція, оскільки вона викликається, коли binary повністю завантажено, але ще не виконано. Вона виконує такі actions, як створення sandbox object, приєднання sandbox struct до kauth credentials, видалення access до mach ports тощо.

Зверніть увагу, що **`_cred_sb_evalutate`** є wrapper-ом над **`sb_evaluate_internal`**. Ця функція отримує передані credentials, а потім виконує evaluation за допомогою функції **`eval`**, яка зазвичай оцінює **platform profile**, що за замовчуванням застосовується до всіх processes, а потім **specific process profile**. Зверніть увагу, що platform profile є одним з основних components **SIP** у macOS.

## Sandboxd

Sandbox також має user daemon, який працює та надає XPC Mach service `com.apple.sandboxd`, прив’язуючи special port 14 (`HOST_SEATBELT_PORT`), який kernel extension використовує для communication з ним. Він надає деякі functions за допомогою MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks, які реєструє Sandbox kext)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, entry point за `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
