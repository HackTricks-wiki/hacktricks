# Mythic

{{#include ../banners/hacktricks-training.md}}

## Що таке Mythic?

Mythic — це open-source, модульний, collaborative command and control (C2) framework, розроблений для red teaming. Він дає змогу операторам керувати агентами (payloads) і розгортати їх у різних операційних системах, зокрема Windows, Linux і macOS. Mythic надає browser UI для multi-operator tasking, обробки файлів, керування SOCKS/rpfwd і генерації payloads.

На відміну від монолітних frameworks, сам репозиторій Mythic **не** містить типів payloads або C2 profiles. Agents, wrappers і C2 profiles зазвичай встановлюються як зовнішні компоненти та можуть оновлюватися незалежно від Mythic core.

### Встановлення

Щоб встановити Mythic, дотримуйтеся інструкцій в офіційному **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Типовий bootstrap із каталогу Mythic має такий вигляд:
```bash
sudo make
sudo ./mythic-cli start
```
Якщо Mythic уже запущений, зазвичай можна додати нового агента або профіль за допомогою `./mythic-cli install github ...`, а потім або перезапустити Mythic, або просто запустити новий компонент безпосередньо.

### Агенти

Mythic підтримує кілька агентів — це **payloads, які виконують завдання на скомпрометованих системах**. Кожен агент можна налаштувати відповідно до конкретних потреб, і він може працювати в різних операційних системах.

За замовчуванням у Mythic не встановлено жодного агента. Агенти спільноти з відкритим кодом розміщені в [**https://github.com/MythicAgents**](https://github.com/MythicAgents), а [**матриця можливостей спільноти**](https://mythicmeta.github.io/overview/agent_matrix.html) допомагає швидко перевірити підтримувані операційні системи, формати payloads, wrappers і C2 profiles.<sup>[[1]](#references)</sup>

Щоб встановити агента з цієї організації, можна виконати:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Форма `sudo -E` корисна, коли ви встановлюєте систему з non-root середовища. За допомогою попередньої команди можна додавати нових агентів, навіть якщо Mythic уже запущено.

### C2 Profiles

C2 profiles у Mythic визначають **як агенти взаємодіють із сервером Mythic**. Вони задають протокол комунікації, методи шифрування та інші налаштування. Створювати та керувати C2 profiles можна через вебінтерфейс Mythic.

За замовчуванням Mythic встановлюється без profiles, однак деякі profiles можна завантажити з repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles), виконавши:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Поточні профілі, важливі для operator, які слід мати на увазі:

- [`http`](https://github.com/MythicC2Profiles/http): базовий асинхронний GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): гнучкіший HTTP traffic із кількома callback domains, fail-over/round-robin rotation, custom headers/query parameters і message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`), розміщеними в cookies, headers, query parameters або body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): формування HTTP messages на основі JSON/TOML, коли static `http` profile надто легко розпізнати.

### Поточні примітки щодо platform

- Багато public agents і profiles тепер встановлюються за допомогою попередньо зібраних remote container images.
Якщо ви зробили fork компонента або внесли до нього patch локально, а Mythic продовжує використовувати стару
поведінку, перевірте згенеровані записи `.env` для `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` і `*_USE_VOLUME`; увімкнення
`*_USE_BUILD_CONTEXT="true"` зазвичай змушує Mythic виконувати rebuild із вашого
локального Docker context замість непомітного повторного використання remote image.
- Browser scripts є однією з найцінніших для operator функцій, що підвищують зручність роботи
в Mythic: вони можуть перетворювати raw command output на tables, screenshot
viewers, download links, search links і buttons, які безпосередньо видають follow-on
tasking з UI. Поточні збірки Mythic дозволяють кожному operator зберігати
власні scripts, вмикати або вимикати їх глобально чи для окремої task, а найкращі результати
отримуються, коли agents повертають структурований JSON замість plaintext. Це особливо
корисно для повторюваних workflow із `ls`, `ps`, triage і file-browser.<sup>[[4]](#references)[[6]](#references)</sup>
- Новіші збірки Mythic також підтримують interactive tasking і Push C2 patterns,
що зменшують потребу в polling через `sleep 0` під час операцій із великим навантаженням
PTY/SOCKS/rpfwd. Якщо agent/profile це підтримує, зазвичай це створює менше overhead,
ніж постійно надсилати запити до server лише для підтримання працездатності interactive
channel.<sup>[[3]](#references)</sup>
- Поточні Mythic builders ери 3.4 краще враховують context, ніж це випливає зі старих writeups:
build parameters тепер можна групувати або приховувати залежно від вибраної OS
чи інших build options; payload types можуть оголошувати, чи підтримують вони
кілька C2 profiles або кілька instances одного й того самого C2 в одній build; а
C2 parameter deviations дозволяють agent приховувати fields, які він фактично
не implement. Це важливо, коли ви перемикаєтеся між `http`, `httpx`, `smb`,
`tcp` і `websocket`, оскільки safe/valid build surface більше не є пласкою статичною формою.<sup>[[5]](#references)</sup>
- Якщо ви створюєте custom agent/profile pair і не хочете, щоб Mythic використовував його JSON message format або default crypto у wire traffic, застосуйте
`translation_container`: Mythic видаляє UUID, передає encrypted blob і key material
translator через gRPC та очікує отримати назад agent-native bytes. Це правильний спосіб
підтримати binary protocols, custom framing або agent-side encryption без переписування
всього server.
- Пам’ятайте, що linked/P2P callbacks не лише передають tasking. Потік
`get_tasking` у Mythic також може передавати responses разом із `delegates`,
`socks`, `rpfwd` та `interactive` data. На практиці один egress callback може
обслуговувати inner callbacks і pivot channels в одному polling loop; якщо child
agents виконують власні періодичні check-ins, `get_delegate_tasks=false` не дає
parent випадково спожити queued jobs inner callback.

### Wrapper payloads

Wrapper payloads дають змогу зберегти ту саму agent logic, одночасно змінюючи on-disk representation, яка доставляється або зберігається.

- `service_wrapper`: перетворює інший payload на Windows service executable, що корисно, коли execution path вимагає коректний service binary.
- `scarecrow_wrapper`: обгортає сумісний shellcode за допомогою ScareCrow loader для створення loader-backed outputs, таких як EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo — це Windows agent, написаний на C# із використанням 4.0 .NET Framework, призначений для використання в навчальних пропозиціях SpecterOps.<sup>[[2]](#references)</sup>

Встановіть його за допомогою:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Поточні нотатки щодо build/profile

- Apollo наразі може генерувати payload типів `WinExe`, `Shellcode`, `Service` і `Source`.
- Найчастіше використовувані профілі Apollo — `http`, `httpx`, `smb`, `tcp` і `websocket`.
- `httpx` зазвичай є більш гнучким варіантом, коли потрібні ротація доменів, підтримка proxy, власне розміщення повідомлень і transforms замість старішого статичного профілю `http`.
- Apollo є одним із найбільш функціональних community agents і наразі надає інтеграції на стороні Mythic, як-от browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2 і P2P routing.
- Apollo підтримує wrapper payloads, як-от `service_wrapper` і `scarecrow_wrapper`.
- Apollo підтримує dynamic command loading, тому можна залишити initial payload компактним і завантажувати додаткові commands або Forge modules пізніше, замість компіляції всіх post-ex можливостей у перший build.
- Під час генерації shellcode output поточний builder Apollo також надає варіанти формату Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) і поведінку Donut bypass (`None`, `Abort on fail`, `Continue on fail`). Це корисно, якщо кінцевою метою є повторне обгортання shellcode за допомогою `service_wrapper`, `scarecrow_wrapper` або custom loader.
- `register_file` і `register_assembly` є staging primitives для `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` і `powerpick`. У поточних build Apollo ці staged artifacts кешуються на стороні client як захищені DPAPI AES256 blobs.
- Результати `ls` і `ps` особливо добре інтегруються з browser scripts і file/process browser Mythic, що помітно пришвидшує operator triage у collaborative operations.
- Fork-and-run jobs Apollo успадковують налаштування sacrificial process із
`spawnto_x86` / `spawnto_x64`, успадковують вибір parent із `ppid`, а потім
використовують поточний injection primitive. На практиці це означає, що
налаштування OPSEC для однієї команди часто впливають на
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` і
`spawn` одночасно.
- Поточні документовані injection backends Apollo включають `CreateRemoteThread`,
`QueueUserAPC` (у стилі early-bird) і `NtCreateThreadEx` через syscalls. Використовуйте
`get_injection_techniques` перед гучними post-exploitation operations і
`set_injection_technique`, якщо потрібно перейти від primitive, який
конфліктує з target або командою, яку ви хочете запустити.
- `blockdlls` впливає лише на sacrificial processes, створені для post-exploitation
jobs. У поєднанні з менш підозрілим `spawnto_x64` target, ніж стандартний
bare `rundll32.exe`, це одна з найпростіших змін на стороні Apollo, яку можна
внести перед виконанням assembly/PowerShell-heavy tasking.

Цей agent має багато commands, завдяки чому він дуже схожий на Beacon від Cobalt Strike, але з деякими додатковими можливостями. Серед них він підтримує:

### Common actions

- `cat`: Вивести вміст файлу
- `cd`: Змінити поточний робочий каталог
- `cp`: Скопіювати файл з одного розташування в інше
- `ls`: Вивести список файлів і каталогів у поточному каталозі або за вказаним шляхом
- `ifconfig`: Отримати інформацію про network adapters та interfaces
- `netstat`: Отримати інформацію про TCP- і UDP-з'єднання
- `pwd`: Вивести поточний робочий каталог
- `ps`: Вивести список запущених процесів у target system (із додатковою інформацією)
- `jobs`: Вивести список усіх запущених jobs, пов'язаних із long-running tasking
- `download`: Завантажити файл із target system на локальну машину
- `upload`: Завантажити файл із локальної машини на target system
- `reg_query`: Виконати query registry keys і values у target system
- `reg_write_value`: Записати нове value у вказаний registry key
- `sleep`: Змінити sleep interval agent, який визначає, як часто він встановлює зв'язок із Mythic server
- І багато інших — використовуйте `help`, щоб переглянути повний список доступних commands.

### Privilege escalation

- `getprivs`: Увімкнути якомога більше privileges у token поточного thread
- `getsystem`: Відкрити handle до winlogon і дублювати token, фактично підвищивши privileges до рівня SYSTEM
- `make_token`: Створити нову logon session і застосувати її до agent, що дозволяє impersonation іншого user
- `steal_token`: Викрасти primary token з іншого process, що дозволяє agent impersonate user цього process
- `pth`: Pass-the-Hash attack, який дозволяє agent authenticate як user, використовуючи його NTLM hash без потреби у plaintext password
- `mimikatz`: Запустити Mimikatz commands для отримання credentials, hashes та іншої sensitive information із memory або SAM database
- `rev2self`: Повернути token agent до його primary token, фактично скинувши privileges до початкового рівня
- `ppid`: Змінити parent process для post-exploitation jobs, вказавши новий parent process ID, що забезпечує кращий контроль над execution context job
- `printspoofer`: Виконати PrintSpoofer commands для обходу security measures print spooler, що дозволяє privilege escalation або code execution
- `dcsync`: Синхронізувати Kerberos keys user із local machine, що дозволяє offline password cracking або подальші attacks
- `ticket_cache_add`: Додати Kerberos ticket до поточної або вказаної logon session, що дозволяє повторне використання ticket або impersonation

### Process execution

- `assembly_inject`: Дозволяє inject .NET assembly loader у remote process
- `blockdlls`: Заблокувати завантаження DLL без підпису Microsoft у post-exploitation jobs
- `execute_assembly`: Виконати .NET assembly у context agent
- `execute_coff`: Виконати COFF file у memory, що дозволяє in-memory execution compiled code
- `execute_pe`: Виконати unmanaged executable (PE)
- `keylog_inject`: Inject keylogger в інший process і передавати натискання клавіш назад до keylog view Mythic
- `screenshot` / `screenshot_inject`: Отримати поточний desktop безпосередньо або
шляхом injection screenshot assembly у target process/session
- `get_injection_techniques`: Показати доступні injection techniques і поточну вибрану
- `inline_assembly`: Виконати .NET assembly у disposable AppDomain, що дозволяє тимчасове виконання code без впливу на main process agent
- `register_assembly`: Зареєструвати .NET assembly для подальшого execution
- `register_file`: Зареєструвати file у agent cache для подальшого `execute_*` або PowerShell tasking
- `run`: Виконати binary у target system, використовуючи system PATH для пошуку executable
- `set_injection_technique`: Змінити injection primitive, який використовується post-exploitation jobs
- `shinject`: Inject shellcode у remote process, що дозволяє in-memory execution arbitrary code
- `inject`: Inject agent shellcode у remote process, що дозволяє in-memory execution code agent
- `spawn`: Створити нову agent session у вказаному executable, що дозволяє виконання shellcode у новому process
- `spawnto_x64` і `spawnto_x86`: Змінити default binary, який використовується в post-exploitation jobs, на вказаний path замість `rundll32.exe` без params, що є дуже гучним.

### Mythic Forge

Це дозволяє **завантажувати COFF/BOF** files із Mythic Forge — repository pre-compiled payloads і tools, які можна виконувати в target system. За допомогою всіх commands, які можна завантажити, можна виконувати common actions у current agent process як BOFs (зазвичай із кращим OPSEC, ніж під час запуску окремого process).

Почніть їх встановлення за допомогою:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Потім використовуйте `forge_collections`, щоб переглянути модулі COFF/BOF з Mythic Forge і вибрати та завантажити їх у пам'ять agent для виконання. За замовчуванням в Apollo додано такі 2 колекції:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Після завантаження модуля він з'явиться у списку як інша команда, наприклад `forge_bof_sa-whoami` або `forge_bof_sa-netuser`.

Для BOF пам'ятайте, що Forge **не** передає Apollo один плоский рядок аргументів. Він зіставляє параметри BOF із форматом типізованого масиву Mythic, а потім передає їх у flow `execute_coff` Apollo. Якщо завантажений через Forge BOF працює нестабільно, перевірте очікувані типи аргументів BOF / entrypoint, а не лише введений вами командний рядок. Також зверніть увагу, що новіший BOF loader Apollo змінив обробку аргументів порівняно зі значно старішими збірками епохи 2.3.1, тому застарілі BOF або старі колекції можуть не працювати лише через зміну очікувань щодо marshaling.

### Виконання PowerShell і scripting

- `powershell_import`: Імпортує новий PowerShell script (.ps1) у cache agent для подальшого виконання
- `powershell`: Виконує PowerShell command у контексті agent, забезпечуючи розширене scripting і automation
- `powerpick`: Інжектить PowerShell loader assembly у sacrificial process і виконує PowerShell command (без powershell logging).
- `psinject`: Виконує PowerShell у вказаному process, забезпечуючи цільове виконання scripts у контексті іншого process
- `shell`: Виконує shell command у контексті agent, подібно до виконання command у cmd.exe

### Lateral Movement

- `jump_psexec`: Використовує техніку PsExec для lateral movement на новий host, спочатку копіюючи executable Apollo agent (apollo.exe) і виконуючи його.
- `jump_wmi`: Використовує техніку WMI для lateral movement на новий host, спочатку копіюючи executable Apollo agent (apollo.exe) і виконуючи його.
- `link` і `unlink`: Створюють і розривають P2P-з'єднання (наприклад, через SMB/TCP) між callbacks.
- `wmiexecute`: Виконує command у локальній або вказаній remote system за допомогою WMI, з optional credentials для impersonation.
- `net_dclist`: Отримує список domain controllers для вказаного domain, що корисно для визначення потенційних targets для lateral movement.
- `net_localgroup`: Виводить список local groups на вказаному computer; якщо computer не вказано, використовується localhost.
- `net_localgroup_member`: Отримує membership локальної group для вказаної group на локальному або remote computer, що дає змогу виконувати enumeration користувачів у певних groups.
- `net_shares`: Виводить список remote shares і їхню доступність на вказаному computer, що корисно для визначення потенційних targets для lateral movement.
- `socks`: Увімкнює compliant із SOCKS 5 proxy у target network, забезпечуючи tunneling traffic через compromised host. Сумісний з такими tools, як proxychains.
- `rpfwd`: Починає listening на вказаному port на target host і пересилає traffic через Mythic на remote IP і port, забезпечуючи remote access до services у target network.
- `listpipes`: Виводить список усіх named pipes у локальній system, що може бути корисним для lateral movement або privilege escalation через взаємодію з IPC mechanisms.

Щоб переглянути low-level WMI execution primitives, які використовуються під `jump_wmi` або `wmiexecute`, дивіться [WmiExec](lateral-movement/wmiexec.md). Для ширших pivoting patterns дивіться [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Різні команди
- `help`: Відображає детальну інформацію про конкретні commands або загальну інформацію про всі доступні commands в agent.
- `clear`: Позначає tasks як 'cleared', щоб agents не могли їх отримати. Можна вказати `all`, щоб очистити всі tasks, або `task Num`, щоб очистити конкретний task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon — це Golang agent, який компілюється у **Linux і macOS** executables.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Поточні примітки щодо build/profile

- Поточні збірки Poseidon призначені для Linux і macOS на `x86_64` та `arm64`.
- Підтримувані формати виводу включають нативні виконувані файли, а також outputs у стилі shared library, як-от `dylib` і `so`.
- Poseidon підтримує `http`, `websocket`, `tcp` і `dynamichttp`, а поточні builders надають налаштування multi-egress, такі як `egress_order` і пороги failover.
- Поточні capability metadata Poseidon також рекламують browser scripts, інтеграцію з file/process browser, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd і P2P, тож він може працювати як повноцінний pivot node для Linux/macOS, а не лише як простий remote shell.
- Build-time options, такі як `proxy_bypass` і `garble`, варто перевірити, коли потрібна чистіша мережева поведінка або додаткова Go binary obfuscation.
- `pty` — одна з найкорисніших нових quality-of-life команд для Linux/macOS
операцій, оскільки вона відкриває інтерактивний PTY і може надати порт на стороні Mythic
для повнішої взаємодії з terminal без використання старішого workaround
`sleep 0` + SOCKS.
- Поточна документація Poseidon особливо цікава для macOS-heavy
tradecraft: `jxa` виконує JavaScript for Automation in-memory,
`screencapture` захоплює desktop користувача, який увійшов у систему,
`clipboard_monitor` передає зміни pasteboard, `execute_library` завантажує локальний dylib
і викликає його функцію, а `libinject` змушує віддалений process завантажити dylib із диска.
- Для довготривалих jobs пам’ятайте, що Poseidon виконує post-exploitation роботу
в goroutines/threads, які є cooperative, а не такими, що їх можна примусово завершити. У
документації також прямо зазначено, що наразі немає вбудованої agent
obfuscation, тому tradecraft на рівні build/profile має більше значення, ніж у
сильно обфускованих commercial implants.

Для macOS-specific tradecraft, пов’язаного з операціями на базі Mythic, зловживанням JAMF або ідеями MDM-as-C2, перегляньте [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Під час використання в Linux або macOS він має кілька цікавих команд:

### Common actions

- `cat`: Вивести вміст файлу
- `cd`: Змінити поточний working directory
- `chmod`: Змінити permissions файлу
- `config`: Переглянути поточну config та інформацію про host
- `cp`: Скопіювати файл з одного location до іншого
- `curl`: Виконати один web request з optional headers і method
- `upload`: Завантажити файл на target
- `download`: Завантажити файл із target system на local machine
- І багато іншого

### Search Sensitive Information

- `triagedirectory`: Знайти цікаві файли в directory на host, наприклад sensitive files або credentials.
- `getenv`: Отримати всі поточні environment variables.

### macOS-specific tradecraft

- `jxa`: Виконати JavaScript for Automation in-memory через `OSAScript`, що
корисно для native macOS post-exploitation без запису окремих script
files.
- `clipboard_monitor`: Опитувати pasteboard і повідомляти зміни назад до Mythic,
що зручно для workflows викрадення credentials/token, які залежать від copy/paste.
- `screencapture`: Захопити desktop користувача в macOS.
- `execute_library`: Завантажити dylib із диска та викликати конкретну exported function.
- `libinject`: Inject shellcode stub, який змушує інший macOS process завантажити dylib із диска.
- `persist_launchd`: Створити persistence через LaunchAgent / LaunchDaemon безпосередньо з agent.

### Move laterally

- `ssh`: Підключитися до host через SSH, використовуючи designated credentials, і відкрити PTY без запуску ssh.
- `sshauth`: Підключитися до вказаних host(s), використовуючи designated credentials. Також це можна використовувати для виконання конкретної команди на remote hosts через SSH або для SCP files.
- `link_tcp`: З’єднатися з іншим agent через TCP, забезпечуючи direct communication між agents.
- `link_webshell`: З’єднатися з agent за допомогою webshell P2P profile, забезпечуючи remote access до web interface agent.
- `rpfwd`: Запустити або зупинити Reverse Port Forward, забезпечуючи remote access до services у target network.
- `socks`: Запустити або зупинити SOCKS5 proxy у target network, забезпечуючи tunneling traffic через compromised host. Сумісний з tools на кшталт proxychains.
- `portscan`: Просканувати host(s) на наявність open ports, що корисно для визначення potential targets для lateral movement або подальших атак.

### Process execution

- `shell`: Виконати одну shell command через /bin/sh, забезпечуючи direct execution commands у target system.
- `run`: Виконати command із диска з arguments, забезпечуючи execution binaries або scripts у target system.
- `pty`: Відкрити інтерактивний PTY, забезпечуючи direct interaction із shell у target system.

## References

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
