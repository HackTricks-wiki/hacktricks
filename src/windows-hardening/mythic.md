# Mythic

{{#include ../banners/hacktricks-training.md}}

## Що таке Mythic?

Mythic — це open-source, модульний, collaborative command and control (C2) framework, призначений для red teaming. Він дає змогу операторам керувати агентами (payloads) і розгортати їх у різних операційних системах, зокрема Windows, Linux і macOS. Mythic надає browser UI для tasking кількох операторів, роботи з файлами, керування SOCKS/rpfwd і генерації payloads.

На відміну від монолітних frameworks, сам репозиторій Mythic **не містить** типів payloads або C2 profiles. Agents, wrappers і C2 profiles зазвичай встановлюються як зовнішні компоненти та можуть оновлюватися незалежно від ядра Mythic.

### Встановлення

Щоб встановити Mythic, дотримуйтеся інструкцій в офіційному **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Типовий bootstrap із каталогу Mythic має такий вигляд:
```bash
sudo make
sudo ./mythic-cli start
```
Якщо Mythic уже запущено, зазвичай можна додати нового agent або profile за допомогою `./mythic-cli install github ...`, а потім або перезапустити Mythic, або просто запустити новий компонент безпосередньо.

### Agents

Mythic підтримує кілька agent, тобто **payload, які виконують завдання на скомпрометованих системах**. Кожен agent можна налаштувати відповідно до конкретних потреб, і він може працювати в різних операційних системах.

За замовчуванням Mythic не має встановлених agent. Agent з open-source спільноти доступні в [**https://github.com/MythicAgents**](https://github.com/MythicAgents), а [**матриця можливостей спільноти**](https://mythicmeta.github.io/overview/agent_matrix.html) допомагає швидко перевірити підтримувані операційні системи, формати payload, wrappers і C2 profiles.

Щоб встановити agent із цієї org, виконайте:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Форма `sudo -E` корисна, коли ви встановлюєте з non-root середовища. Ви можете додавати нові агенти за допомогою попередньої команди, навіть якщо Mythic уже запущено.

### C2 Profiles

C2 profiles у Mythic визначають, **як агенти взаємодіють із сервером Mythic**. Вони задають протокол зв’язку, методи шифрування та інші налаштування. Ви можете створювати та керувати C2 profiles через вебінтерфейс Mythic.

За замовчуванням Mythic встановлюється без профілів, однак деякі профілі можна завантажити з репозиторію [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles), виконавши:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Актуальні профілі, важливі для operator, які слід враховувати:

- [`http`](https://github.com/MythicC2Profiles/http): базовий асинхронний GET/POST-трафік.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): гнучкіший HTTP-трафік із кількома callback-доменами, перемиканням у разі відмови/ротацією round-robin, користувацькими заголовками/параметрами запитів і перетвореннями повідомлень (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append>), розміщеними в cookies, заголовках, параметрах запитів або тілі.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): формування HTTP-повідомлень на основі JSON/TOML, коли статичний профіль `http` надто легко розпізнати.

### Поточні нотатки щодо платформи

- Багато public agents і profiles тепер встановлюються з попередньо зібраними remote container images.
Якщо ви зробили fork компонента або внесли до нього локальні зміни, а Mythic продовжує використовувати стару поведінку, перевірте згенеровані записи `.env` для `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` і `*_USE_VOLUME`; увімкнення
`*_USE_BUILD_CONTEXT="true"` зазвичай змушує Mythic перебудувати компонент із вашого
локального Docker context замість непомітного повторного використання remote image.
- Browser scripts є однією з найцінніших функцій Mythic для покращення роботи operator:
вони можуть перетворювати необроблений вивід команд на таблиці, переглядачі скриншотів, посилання для завантаження, посилання для пошуку та кнопки, які безпосередньо з UI створюють follow-on tasking.
Поточні збірки Mythic дають змогу кожному operator зберігати власні scripts,
вмикати або вимикати їх глобально чи для окремих tasks, а найкращі результати досягаються,
коли agents повертають структурований JSON, а не plaintext. Це особливо корисно
для повторюваних workflow з `ls`, `ps`, triage і file browser.
- Новіші збірки Mythic також підтримують interactive tasking і Push C2 patterns,
які зменшують потребу в polling через `sleep 0` під час операцій із великим використанням PTY/SOCKS/rpfwd.
Коли agent/profile це підтримує, такий підхід зазвичай створює менше навантаження,
ніж постійно надсилати запити до сервера лише для підтримки інтерактивного каналу.
- Сучасні builders Mythic епохи 3.4 краще враховують context, ніж це випливає зі старих описів:
тепер build parameters можна групувати або приховувати залежно від вибраної OS
чи інших build options, payload types можуть вказувати, чи підтримують вони
кілька C2 profiles або кілька instances одного C2 в одному build,
а відхилення C2 parameters дають змогу agent приховувати поля, які він фактично
не реалізує. Це важливо, коли ви перемикаєтеся між `http`, `httpx`, `smb`,
`tcp` і `websocket`, оскільки безпечна/допустима поверхня build більше не є
плоскою статичною формою.
- Якщо ви створюєте custom agent/profile pair і не хочете, щоб Mythic використовував
його JSON message format або default crypto у wire-трафіку, скористайтеся
`translation_container`: Mythic видаляє UUID, передає зашифрований blob і key material
translator через gRPC та очікує у відповідь agent-native bytes. Це правильний спосіб
підтримати binary protocols, custom framing або encryption на боці agent без переписування
всього сервера.
- Пам’ятайте, що linked/P2P callbacks не лише передають tasking. Потік Mythic
`get_tasking` також може переносити responses, а також `delegates`,
`socks`, `rpfwd` і `interactive` data. На практиці один egress callback може обслуговувати
inner callbacks і pivot channels у тому самому polling loop; якщо child agents виконують
власні періодичні check-ins, параметр `get_delegate_tasks=false` не дає parent випадково
забрати jobs, поставлені в чергу для inner callback.

### Wrapper payloads

Wrapper payloads дають змогу зберігати ту саму логіку agent, змінюючи on-disk representation,
яка доставляється або зберігається.

- `service_wrapper`: перетворює інший payload на Windows service executable, що корисно,
коли execution path вимагає дійсний service binary.
- `scarecrow_wrapper`: обгортає сумісний shellcode за допомогою ScareCrow loader, щоб створювати
loader-backed outputs, такі як EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo — це Windows agent, написаний на C# з використанням 4.0 .NET Framework,
призначений для використання у training offerings SpecterOps.

Встановіть його за допомогою:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Поточні примітки щодо build/profile

- Apollo наразі може створювати payloads `WinExe`, `Shellcode`, `Service` і `Source`.
- Найчастіше використовувані профілі Apollo: `http`, `httpx`, `smb`, `tcp` і `websocket`.
- `httpx` зазвичай є гнучкішим варіантом, коли потрібні ротація доменів, підтримка proxy, розміщення custom message і message transforms замість старішого статичного профілю `http`.
- Apollo є одним із найбільш функціональних community agents і наразі надає інтеграції на стороні Mythic, зокрема browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2 і P2P routing.
- Apollo підтримує wrapper payloads, такі як `service_wrapper` і `scarecrow_wrapper`.
- Apollo підтримує dynamic command loading, тому можна залишити початковий payload компактним і завантажувати додаткові команди або Forge modules пізніше, замість компіляції всіх post-ex можливостей у перший build.
- Під час створення shellcode output поточний builder Apollo також надає варіанти формату Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) і поведінку Donut bypass (`None`, `Abort on fail`, `Continue on fail`). Це корисно, якщо кінцева мета — повторно обгорнути shellcode за допомогою `service_wrapper`, `scarecrow_wrapper` або custom loader.
- `register_file` і `register_assembly` є staging primitives для `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` і `powerpick`. У поточних build Apollo ці staged artifacts кешуються на стороні client як захищені DPAPI AES256 blobs.
- Результати `ls` і `ps` особливо добре інтегруються з browser scripts і file/process browser Mythic, що помітно пришвидшує operator triage у collaborative operations.
- Fork-and-run jobs Apollo успадковують налаштування sacrificial process із
`spawnto_x86` / `spawnto_x64`, вибір parent process із `ppid`, а потім
використовують поточний injection primitive. На практиці це означає, що
OPSEC tuning для однієї команди часто впливає на `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` і `spawn`
одночасно.
- Поточні документовані injection backends Apollo включають `CreateRemoteThread`,
`QueueUserAPC` (у стилі early-bird) і `NtCreateThreadEx` через syscalls. Використовуйте
`get_injection_techniques` перед шумним post-exploitation і
`set_injection_technique`, якщо потрібно перейти від primitive, який конфліктує
з target або командою, яку потрібно запустити.
- `blockdlls` впливає лише на sacrificial processes, створені для post-exploitation
jobs. У поєднанні з менш підозрілим target `spawnto_x64`, ніж типовий
bare `rundll32.exe`, це одна з найпростіших змін на стороні Apollo, яку можна внести
перед виконанням assembly/PowerShell-heavy tasking.

Цей agent має багато команд, завдяки чому він дуже схожий на Beacon від Cobalt Strike, але з деякими додатковими можливостями. Серед іншого, він підтримує:

### Типові дії

- `cat`: Вивести вміст файлу
- `cd`: Змінити поточний working directory
- `cp`: Скопіювати файл з одного розташування в інше
- `ls`: Вивести список файлів і директорій у поточній директорії або вказаному path
- `ifconfig`: Отримати інформацію про network adapters та interfaces
- `netstat`: Отримати інформацію про TCP- і UDP-з'єднання
- `pwd`: Вивести поточний working directory
- `ps`: Вивести список запущених processes у target system (з додатковою інформацією)
- `jobs`: Вивести список усіх запущених jobs, пов'язаних із long-running tasking
- `download`: Завантажити файл із target system на локальну машину
- `upload`: Завантажити файл із локальної машини на target system
- `reg_query`: Виконати query registry keys і values у target system
- `reg_write_value`: Записати нове value у вказаний registry key
- `sleep`: Змінити sleep interval agent, який визначає, як часто він зв'язується із Mythic server
- Та багато інших; використовуйте `help`, щоб переглянути повний список доступних команд.

### Підвищення привілеїв

- `getprivs`: Увімкнути якомога більше privileges у token поточного thread
- `getsystem`: Відкрити handle до winlogon і дублювати token, фактично підвищивши privileges до рівня SYSTEM
- `make_token`: Створити нову logon session і застосувати її до agent, що дає змогу impersonate іншого user
- `steal_token`: Викрасти primary token з іншого process, що дає змогу agent impersonate user цього process
- `pth`: Pass-the-Hash attack, що дає змогу agent authenticate як user за допомогою його NTLM hash без потреби у plaintext password
- `mimikatz`: Запустити команди Mimikatz для вилучення credentials, hashes та іншої sensitive information із memory або SAM database
- `rev2self`: Повернути token agent до його primary token, фактично знизивши privileges до початкового рівня
- `ppid`: Змінити parent process для post-exploitation jobs, вказавши новий parent process ID, що дає кращий контроль над job execution context
- `printspoofer`: Виконати команди PrintSpoofer для обходу security measures print spooler, що дає змогу підвищити privileges або виконати code
- `dcsync`: Синхронізувати Kerberos keys user з локальною машиною, що дає змогу виконувати offline password cracking або подальші attacks
- `ticket_cache_add`: Додати Kerberos ticket до поточної logon session або вказаної session, що дає змогу повторно використовувати ticket або виконувати impersonation

### Виконання процесів

- `assembly_inject`: Дає змогу inject .NET assembly loader у remote process
- `blockdlls`: Блокувати завантаження DLL без підпису Microsoft у post-exploitation jobs
- `execute_assembly`: Виконати .NET assembly у context agent
- `execute_coff`: Виконати COFF file у memory, що дає змогу виконувати compiled code у memory
- `execute_pe`: Виконати unmanaged executable (PE)
- `keylog_inject`: Inject keylogger в інший process і передавати keystrokes до keylog view Mythic
- `screenshot` / `screenshot_inject`: Зробити capture поточного desktop безпосередньо або
шляхом injection screenshot assembly у target process/session
- `get_injection_techniques`: Показати доступні injection techniques і поточну вибрану technique
- `inline_assembly`: Виконати .NET assembly у disposable AppDomain, що дає змогу тимчасово виконати code без впливу на main process agent
- `register_assembly`: Зареєструвати .NET assembly для подальшого виконання
- `register_file`: Зареєструвати file у agent cache для подальшого `execute_*` або PowerShell tasking
- `run`: Виконати binary у target system, використовуючи system PATH для пошуку executable
- `set_injection_technique`: Змінити injection primitive, який використовується post-exploitation jobs
- `shinject`: Inject shellcode у remote process, що дає змогу виконувати довільний code у memory
- `inject`: Inject agent shellcode у remote process, що дає змогу виконувати code agent у memory
- `spawn`: Створити нову agent session у вказаному executable, що дає змогу виконувати shellcode у новому process
- `spawnto_x64` і `spawnto_x86`: Змінити default binary, який використовується в post-exploitation jobs, на вказаний path замість `rundll32.exe` без params, що є дуже шумним.

### Mythic Forge

Це дає змогу **load COFF/BOF** files із Mythic Forge — repository pre-compiled payloads і tools, які можна виконувати на target system. За допомогою всіх доступних для load команд можна буде виконувати типові дії в поточному agent process як BOFs (зазвичай із кращим OPSEC, ніж під час spawn окремого process).

Почніть їх встановлення за допомогою:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Потім використайте `forge_collections`, щоб показати модулі COFF/BOF із Mythic Forge і мати змогу вибрати та завантажити їх у пам'ять агента для виконання. За замовчуванням в Apollo додано такі 2 колекції:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Після завантаження модуля він з'явиться у списку як інша команда, наприклад `forge_bof_sa-whoami` або `forge_bof_sa-netuser`.

Для BOF пам'ятайте, що Forge **не** передає Apollo один плоский рядок аргументів. Він зіставляє параметри BOF із форматом типізованого масиву Mythic, а потім передає їх у процес `execute_coff` в Apollo. Якщо завантажений через Forge BOF працює дивно, перевірте очікувані типи аргументів BOF і entrypoint, а не лише введений вами командний рядок. Також зверніть увагу, що новіший BOF loader в Apollo змінив обробку аргументів порівняно зі значно старішими збірками епохи 2.3.1, тому застарілі BOF або старі колекції можуть не працювати суто через зміну очікувань щодо marshaling.

### Виконання PowerShell і скриптів

- `powershell_import`: Імпортує новий PowerShell-скрипт (.ps1) у кеш агента для подальшого виконання
- `powershell`: Виконує команду PowerShell у контексті агента, забезпечуючи розширені можливості скриптингу й автоматизації
- `powerpick`: Інжектить збірку PowerShell loader у sacrificial process і виконує команду PowerShell (без PowerShell logging).
- `psinject`: Виконує PowerShell у вказаному процесі, забезпечуючи цільове виконання скриптів у контексті іншого процесу
- `shell`: Виконує shell-команду в контексті агента, подібно до запуску команди в cmd.exe

### Lateral Movement

- `jump_psexec`: Використовує техніку PsExec для lateral movement на новий хост: спочатку копіює виконуваний файл агента Apollo (apollo.exe), а потім запускає його.
- `jump_wmi`: Використовує техніку WMI для lateral movement на новий хост: спочатку копіює виконуваний файл агента Apollo (apollo.exe), а потім запускає його.
- `link` і `unlink`: Створюють і розривають P2P-з'єднання (наприклад, через SMB/TCP) між callback.
- `wmiexecute`: Виконує команду на локальній або вказаній віддаленій системі за допомогою WMI, з необов'язковими обліковими даними для impersonation.
- `net_dclist`: Отримує список domain controllers для вказаного домену, що допомагає визначити потенційні цілі для lateral movement.
- `net_localgroup`: Виводить список локальних груп на вказаному комп'ютері; якщо комп'ютер не вказано, використовується localhost.
- `net_localgroup_member`: Отримує членство в локальній групі для вказаної групи на локальному або віддаленому комп'ютері, що дає змогу виконувати enumeration користувачів у певних групах.
- `net_shares`: Виводить список віддалених shares і відомості про доступ до них на вказаному комп'ютері, що допомагає визначити потенційні цілі для lateral movement.
- `socks`: Увімкнює SOCKS 5 compliant proxy у цільовій мережі, забезпечуючи тунелювання трафіку через compromised host. Сумісний з такими інструментами, як proxychains.
- `rpfwd`: Починає прослуховування вказаного порту на цільовому хості та пересилає трафік через Mythic на віддалені IP і порт, забезпечуючи віддалений доступ до сервісів у цільовій мережі.
- `listpipes`: Виводить список усіх named pipes у локальній системі, що може бути корисним для lateral movement або privilege escalation через взаємодію з IPC-механізмами.

Докладніше про низькорівневі примітиви виконання WMI, які використовуються всередині `jump_wmi` або `wmiexecute`, див. у [WmiExec](lateral-movement/wmiexec.md). Про ширші шаблони pivoting див. у [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Різні команди
- `help`: Відображає докладну інформацію про конкретні команди або загальну інформацію про всі доступні команди агента.
- `clear`: Позначає завдання як 'cleared', щоб агенти не могли їх отримати. Можна вказати `all`, щоб очистити всі завдання, або `task Num`, щоб очистити конкретне завдання.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon — це Golang-агент, який компілюється у виконувані файли для **Linux і macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Поточні нотатки щодо build/profile

- Поточні builds Poseidon націлені на Linux і macOS для `x86_64` та `arm64`.
- Підтримувані формати виводу включають native executables, а також outputs у стилі shared library, такі як `dylib` і `so`.
- Poseidon підтримує `http`, `websocket`, `tcp` і `dynamichttp`, а поточні builders надають налаштування multi-egress, такі як `egress_order` і failover thresholds.
- Поточні capability metadata Poseidon також рекламують browser scripts, інтеграцію file/process browser, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd і P2P, тому він може працювати як повноцінний Linux/macOS pivot node, а не лише як простий remote shell.
- Build-time options, такі як `proxy_bypass` і `garble`, варто перевіряти, коли потрібна або чистіша мережна поведінка, або додаткова Go binary obfuscation.
- `pty` — одна з найкорисніших нових quality-of-life команд для Linux/macOS
операцій, оскільки відкриває інтерактивний PTY і може надати порт на стороні Mythic
для повнішої взаємодії з терміналом без використання старого workaround
`sleep 0` + SOCKS.
- Поточна документація Poseidon особливо цікава для macOS-heavy
tradecraft: `jxa` виконує JavaScript for Automation in-memory,
`screencapture` захоплює desktop користувача, `clipboard_monitor` передає
зміни pasteboard, `execute_library` завантажує локальний dylib і викликає
його функцію, а `libinject` змушує віддалений process завантажити dylib із диска.
- Для довготривалих jobs пам'ятайте, що Poseidon виконує post-exploitation роботу
в goroutines/threads, які є cooperative, а не такими, що можуть бути
примусово завершені. Документація також прямо зазначає, що наразі немає вбудованої
agent obfuscation, тому tradecraft на рівні build/profile має більше значення,
ніж у сильно обфускованих commercial implants.

Для macOS-specific tradecraft навколо операцій на базі Mythic, JAMF abuse або ідей MDM-as-C2 перевірте [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Під час використання в Linux або macOS він має кілька цікавих команд:

### Типові дії

- `cat`: Вивести вміст файлу
- `cd`: Змінити поточний working directory
- `chmod`: Змінити permissions файлу
- `config`: Переглянути поточну config та інформацію про host
- `cp`: Скопіювати файл з одного location до іншого
- `curl`: Виконати один web request з optional headers і method
- `upload`: Завантажити файл на target
- `download`: Завантажити файл із target system на local machine
- І багато іншого

### Пошук чутливої інформації

- `triagedirectory`: Знайти цікаві файли в directory на host, наприклад sensitive files або credentials.
- `getenv`: Отримати всі поточні environment variables.

### macOS-specific tradecraft

- `jxa`: Виконати JavaScript for Automation in-memory через `OSAScript`, що
корисно для native macOS post-exploitation без створення окремих script
files.
- `clipboard_monitor`: Опитувати pasteboard і повідомляти зміни назад до Mythic,
що зручно для workflows крадіжки credentials/tokens, які залежать від copy/paste.
- `screencapture`: Зробити capture desktop користувача в macOS.
- `execute_library`: Завантажити dylib з диска та викликати певну exported function.
- `libinject`: Inject shellcode stub, який змушує інший macOS process завантажити dylib із диска.
- `persist_launchd`: Створити persistence через LaunchAgent / LaunchDaemon безпосередньо з agent.

### Латеральне переміщення

- `ssh`: Підключитися до host через SSH із використанням designated credentials і відкрити PTY без spawning ssh.
- `sshauth`: Підключитися до вказаних host(s) із використанням designated credentials. Також можна використати цю команду для виконання певної команди на remote hosts через SSH або для SCP files.
- `link_tcp`: Створити link до іншого agent через TCP, забезпечуючи direct communication між agents.
- `link_webshell`: Створити link до agent за допомогою webshell P2P profile, забезпечуючи remote access до web interface agent.
- `rpfwd`: Запустити або зупинити Reverse Port Forward, забезпечуючи remote access до services у target network.
- `socks`: Запустити або зупинити SOCKS5 proxy у target network, забезпечуючи tunneling traffic через compromised host. Сумісний з tools на кшталт proxychains.
- `portscan`: Просканувати host(s) на наявність open ports, що корисно для ідентифікації potential targets для lateral movement або подальших атак.

### Виконання process

- `shell`: Виконати одну shell command через /bin/sh, забезпечуючи direct execution commands у target system.
- `run`: Виконати command із диска з arguments, забезпечуючи execution binaries або scripts у target system.
- `pty`: Відкрити інтерактивний PTY, забезпечуючи direct interaction із shell у target system.






## References

- [Матриця функцій Mythic Community Agent](https://mythicmeta.github.io/overview/agent_matrix.html)
- [README Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Основні особливості Mythic v3.2: Interactive Tasking, Push C2 і Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts — документація Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Оновлення Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Трансформація Red Team Ops за допомогою прихованих можливостей Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
