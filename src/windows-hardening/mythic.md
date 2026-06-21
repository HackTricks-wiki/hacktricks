# Mythic

{{#include ../banners/hacktricks-training.md}}

## Що таке Mythic?

Mythic — це open-source, модульний, collaborative framework для command and control (C2), створений для red teaming. Він дозволяє операторам керувати та розгортати agents (payloads) на різних операційних системах, включно з Windows, Linux і macOS. Mythic надає browser UI для multi-operator tasking, file handling, керування SOCKS/rpfwd і генерації payload.

На відміну від monolithic frameworks, сам репозиторій Mythic **не** постачається з payload types або C2 profiles. Agents, wrappers і C2 profiles зазвичай встановлюються як external components і можуть оновлюватися незалежно від core Mythic.

### Installation

Щоб встановити Mythic, дотримуйтесь інструкцій на офіційному **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Звичний bootstrap з каталогу Mythic такий:
```bash
sudo make
sudo ./mythic-cli start
```
Якщо Mythic вже запущено, зазвичай можна додати новий agent або profile за допомогою `./mythic-cli install github ...`, а потім або перезапустити Mythic, або просто запустити новий компонент напряму.

### Agents

Mythic підтримує кілька agents, які є **payloads, що виконують tasks на compromised systems**. Кожен agent можна налаштувати під конкретні потреби, і він може працювати на різних операційних системах.

За замовчуванням у Mythic не встановлено жодного agent. Open-source community agents розміщені в [**https://github.com/MythicAgents**](https://github.com/MythicAgents), а [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) корисна для швидкої перевірки підтримуваних операційних систем, payload formats, wrappers і C2 profiles.

Щоб встановити agent із цієї org, ви можете запустити:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Форма `sudo -E` корисна, коли ви встановлюєте з середовища без root. Ви можете додавати нових агентів попередньою командою, навіть якщо Mythic уже запущено.

### C2 Profiles

C2 profiles у Mythic визначають **як agents communicate with the Mythic server**. Вони вказують communication protocol, encryption methods та інші налаштування. Ви можете створювати та керувати C2 profiles через веб-інтерфейс Mythic.

За замовчуванням Mythic встановлюється без profiles, однак можна завантажити деякі profiles з репозиторію [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles), запустивши:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Current platform notes

- Many public agents and profiles now install with pre-built remote container images.
If you fork a component or patch it locally and Mythic keeps using the old
behavior, inspect the generated `.env` entries for `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, and `*_USE_VOLUME`; enabling
`*_USE_BUILD_CONTEXT="true"` is usually what makes Mythic rebuild from your
local Docker context instead of silently reusing the remote image.
- Browser scripts are one of Mythic's highest-value quality-of-life features
for operators: they can turn raw command output into tables, screenshot
viewers, download links, and buttons that issue follow-on tasking directly
from the UI. This is especially useful for repetitive `ls`, `ps`, triage,
and file-browser workflows.
- Newer Mythic builds also support interactive tasking and Push C2 patterns
that reduce the need for `sleep 0` polling during PTY/SOCKS/rpfwd-heavy
operations. When an agent/profile supports it, this is usually lower-overhead
than hammering the server with constant check-ins just to keep an interactive
channel usable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: wraps compatible shellcode with the ScareCrow loader to generate loader-backed outputs such as EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Поточні нотатки про build/profile

- Apollo наразі може виводити payloads `WinExe`, `Shellcode`, `Service` і `Source`.
- Найчастіше використовувані Apollo profiles — це `http`, `httpx`, `smb`, `tcp` і `websocket`.
- `httpx` зазвичай є більш гнучким варіантом, коли потрібні ротація доменів, підтримка proxy, кастомне розміщення повідомлень і transforms повідомлень замість старішого статичного профілю `http`.
- Apollo підтримує wrapper payloads, такі як `service_wrapper` і `scarecrow_wrapper`.
- `register_file` і `register_assembly` — це staging primitives для `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` і `powerpick`. У поточних збірках Apollo ці staged artifacts кешуються на клієнті як AES256 blobs, захищені DPAPI.
- Результати `ls` і `ps` особливо добре інтегруються з browser scripts і file/process browser Mythic, що помітно пришвидшує triage для operator у спільних операціях.
- Apollo fork-and-run jobs успадковують налаштування sacrificial process від
`spawnto_x86` / `spawnto_x64`, успадковують вибір parent від `ppid`, а
потім використовують поточний selected injection primitive. На практиці це означає,
що ваша OPSEC-налаштування для однієї команди часто впливає на
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` і `spawn`
одночасно.
- Поточні задокументовані Apollo injection backends включають `CreateRemoteThread`,
`QueueUserAPC` (early-bird style) і `NtCreateThreadEx` через syscalls. Використовуйте
`get_injection_techniques` перед noisy post-exploitation і
`set_injection_technique`, якщо потрібно перейти з primitive, який
конфліктує з target або з командою, яку ви хочете виконати.
- `blockdlls` впливає лише на sacrificial processes, створені для post-exploitation
jobs. У поєднанні з менш підозрілим `spawnto_x64` target, ніж стандартний
bare `rundll32.exe`, це одна з найпростіших змін на боці Apollo, яку можна зробити
перед запуском assembly/PowerShell-heavy tasking.

Цей agent має багато команд, що робить його дуже схожим на Beacon у Cobalt Strike, але з деякими extras. Серед них він підтримує:

### Common actions

- `cat`: Вивести вміст файлу
- `cd`: Змінити поточний working directory
- `cp`: Скопіювати файл з одного місця в інше
- `ls`: Перелічити файли та директорії в поточному directory або вказаному path
- `ifconfig`: Отримати network adapters і interfaces
- `netstat`: Отримати інформацію про TCP і UDP connections
- `pwd`: Вивести поточний working directory
- `ps`: Перелічити running processes на target system (з додатковою інформацією)
- `jobs`: Перелічити всі running jobs, пов’язані з long-running tasking
- `download`: Завантажити файл з target system на локальну машину
- `upload`: Завантажити файл з локальної машини на target system
- `reg_query`: Запитати registry keys і values на target system
- `reg_write_value`: Записати нове значення в указаний registry key
- `sleep`: Змінити sleep interval agent'а, який визначає, як часто він виходить на зв’язок із Mythic server
- І багато інших, використовуйте `help`, щоб побачити повний список доступних команд.

### Privilege escalation

- `getprivs`: Увімкнути якомога більше privileges на поточному thread token
- `getsystem`: Відкрити handle до winlogon і дублювати token, фактично підвищуючи privileges до рівня SYSTEM
- `make_token`: Створити нову logon session і застосувати її до agent, дозволяючи impersonation іншого user
- `steal_token`: Викрасти primary token з іншого process, дозволяючи agent impersonate user цього process
- `pth`: Pass-the-Hash attack, що дозволяє agent authenticatе як user, використовуючи їх NTLM hash без потреби в plaintext password
- `mimikatz`: Запустити Mimikatz commands для витягування credentials, hashes та іншої sensitive information з memory або SAM database
- `rev2self`: Повернути token agent'а до його primary token, фактично знизивши privileges назад до початкового рівня
- `ppid`: Змінити parent process для post-exploitation jobs, вказавши новий parent process ID, що дає кращий контроль над execution context job'ів
- `printspoofer`: Виконати PrintSpoofer commands для обходу print spooler security measures, що дозволяє privilege escalation або code execution
- `dcsync`: Синхронізувати Kerberos keys user'а на локальну машину, що дозволяє offline password cracking або подальші attacks
- `ticket_cache_add`: Додати Kerberos ticket до поточної logon session або вказаної, що дозволяє ticket reuse або impersonation

### Process execution

- `assembly_inject`: Дозволяє інжектити .NET assembly loader у remote process
- `blockdlls`: Блокує завантаження DLL, підписаних не Microsoft, у post-exploitation jobs
- `execute_assembly`: Виконує .NET assembly в контексті agent
- `execute_coff`: Виконує COFF file в memory, дозволяючи in-memory execution скомпільованого коду
- `execute_pe`: Виконує unmanaged executable (PE)
- `keylog_inject`: Інжектить keylogger в інший process і передає натискання клавіш назад у Mythic keylog view
- `screenshot` / `screenshot_inject`: Захопити поточний desktop напряму або
через інжекцію screenshot assembly у target process/session
- `get_injection_techniques`: Показати доступні injection techniques і поточну вибрану
- `inline_assembly`: Виконує .NET assembly у disposable AppDomain, дозволяючи тимчасове виконання code без впливу на main process agent'а
- `register_assembly`: Зареєструвати .NET assembly для подальшого виконання
- `register_file`: Зареєструвати файл у cache agent'а для подальшого `execute_*` або PowerShell tasking
- `run`: Виконує binary на target system, використовуючи system PATH для пошуку executable
- `set_injection_technique`: Змінити injection primitive, що використовується post-exploitation jobs
- `shinject`: Інжектить shellcode у remote process, дозволяючи in-memory execution arbitrary code
- `inject`: Інжектить agent shellcode у remote process, дозволяючи in-memory execution code agent'а
- `spawn`: Створює нову session agent'а у вказаному executable, дозволяючи виконання shellcode у новому process
- `spawnto_x64` and `spawnto_x86`: Змінити default binary, що використовується в post-exploitation jobs, на вказаний path замість використання `rundll32.exe` без params, що дуже шумно.

### Mythic Forge

Це дозволяє **завантажувати COFF/BOF** файли з Mythic Forge, який є repository попередньо скомпільованих payloads і tools, що можуть виконуватися на target system. З усіма командами, які можна завантажити, буде можливо виконувати common actions, запускаючи їх у поточному process agent'а як BOFs (зазвичай із кращим OPSEC, ніж створення окремого process).

Почніть установку з:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, use `forge_collections` to show the COFF/BOF modules from the Mythic Forge to be able to select and load them into the agent's memory for execution. By default, the following 2 collections are added in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

After one module is loaded, it'll appear in the list as another command like `forge_bof_sa-whoami` or `forge_bof_sa-netuser`.

For BOFs, remember that Forge does **not** just pass one flat argument string
to Apollo. It maps BOF parameters into Mythic's typed-array format and then
forwards them into Apollo's `execute_coff` flow. If a Forge-loaded BOF behaves
strangely, check the expected BOF argument types / entrypoint rather than only
the command line you typed.

### PowerShell & scripting execution

- `powershell_import`: Імпортує новий PowerShell script (.ps1) у кеш агента для подальшого виконання
- `powershell`: Виконує PowerShell command у контексті агента, дозволяючи advanced scripting and automation
- `powerpick`: Впроваджує PowerShell loader assembly у sacrificial process і виконує PowerShell command (без powershell logging).
- `psinject`: Виконує PowerShell у вказаному process, забезпечуючи targeted execution of scripts у контексті іншого process
- `shell`: Виконує shell command у контексті агента, подібно до запуску command у cmd.exe

### Lateral Movement

- `jump_psexec`: Використовує техніку PsExec для lateral movement на новий host, спочатку копіюючи виконуваний файл агента Apollo (apollo.exe) і запускаючи його.
- `jump_wmi`: Використовує техніку WMI для lateral movement на новий host, спочатку копіюючи виконуваний файл агента Apollo (apollo.exe) і запускаючи його.
- `link` and `unlink`: Створюють і розривають P2P links (наприклад over SMB/TCP) між callbacks.
- `wmiexecute`: Виконує command на local або вказаній remote system using WMI, з optional credentials для impersonation.
- `net_dclist`: Отримує list domain controllers для вказаного domain, корисний для identifying potential targets for lateral movement.
- `net_localgroup`: Виводить local groups на вказаному computer, за замовчуванням localhost, якщо computer не вказано.
- `net_localgroup_member`: Отримує local group membership для вказаної group на local або remote computer, дозволяючи enumeration користувачів у specific groups.
- `net_shares`: Виводить remote shares та їхню доступність на вказаному computer, корисно для identifying potential targets for lateral movement.
- `socks`: Увімкнює SOCKS 5 compliant proxy у target network, дозволяючи tunneling traffic через compromised host. Compatible with tools like proxychains.
- `rpfwd`: Запускає listening на вказаному port на target host і forward'ить traffic через Mythic до remote IP і port, дозволяючи remote access до services у target network.
- `listpipes`: Виводить усі named pipes на local system, що може бути корисно для lateral movement або privilege escalation через взаємодію з IPC mechanisms.

For the lower-level WMI execution primitives used underneath `jump_wmi` or `wmiexecute`, check [WmiExec](lateral-movement/wmiexec.md). For broader pivoting patterns, check [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Показує детальну information про specific commands або загальну information про всі available commands в agent.
- `clear`: Позначає tasks як 'cleared', щоб agents не могли їх підхопити. Ви можете вказати `all`, щоб очистити всі tasks, або `task Num`, щоб очистити specific task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is a Golang agent that compiles into **Linux and macOS** executables.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Current Poseidon builds target Linux and macOS on both `x86_64` and `arm64`.
- Supported output formats include native executables plus shared-library style outputs such as `dylib` and `so`.
- Poseidon supports `http`, `websocket`, `tcp`, and `dynamichttp`, and current builders expose multi-egress settings such as `egress_order` and failover thresholds.
- Build-time options such as `proxy_bypass` and `garble` are worth checking when you need either cleaner network behavior or extra Go binary obfuscation.
- `pty` is one of the most useful newer-quality-of-life commands for Linux/macOS
operations because it opens an interactive PTY and can expose a Mythic-side
port for fuller terminal interaction without resorting to the older `sleep 0`
+ SOCKS workaround.
- Poseidon's current docs are especially interesting for macOS-heavy
tradecraft: `jxa` executes JavaScript for Automation in-memory,
`screencapture` grabs the logged-in desktop, `clipboard_monitor` streams
pasteboard changes, `execute_library` loads a local dylib and calls a
function from it, and `libinject` forces a remote process to load an on-disk
dylib.
- For long-running jobs, remember that Poseidon executes post-exploitation work
in goroutines/threads that are cooperative rather than hard-killable. The
docs also explicitly note that there is currently no built-in agent
obfuscation, so build/profile-level tradecraft matters more than with heavily
obfuscated commercial implants.

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

When used on Linux or macOS it has some interesting commands:

### Common actions

- `cat`: Вивести вміст файла
- `cd`: Змінити поточний робочий каталог
- `chmod`: Змінити права доступу файла
- `config`: Переглянути поточну конфігурацію та інформацію про хост
- `cp`: Скопіювати файл з одного місця в інше
- `curl`: Виконати один web-запит з необов’язковими заголовками та методом
- `upload`: Завантажити файл на ціль
- `download`: Завантажити файл із цільової системи на локальну машину
- And many more

### Search Sensitive Information

- `triagedirectory`: Знайти цікаві файли в каталозі на хості, наприклад чутливі файли або credentials.
- `getenv`: Отримати всі поточні змінні середовища.

### macOS-specific tradecraft

- `jxa`: Виконати JavaScript for Automation in-memory через `OSAScript`, що
корисно для нативного macOS post-exploitation без створення окремих script
files.
- `clipboard_monitor`: Опитувати pasteboard і повідомляти про зміни назад до Mythic,
що зручно для workflow викрадення credentials/token, які залежать від copy/paste.
- `screencapture`: Захопити desktop користувача на macOS.
- `execute_library`: Завантажити dylib з диска і викликати конкретну експортовану функцію.
- `libinject`: Впровадити shellcode stub, який примушує інший macOS process завантажити dylib з диска.
- `persist_launchd`: Створити LaunchAgent / LaunchDaemon persistence безпосередньо з агента.

### Move laterally

- `ssh`: SSH до host, використовуючи призначені credentials, і відкрити PTY без запуску ssh.
- `sshauth`: SSH до вказаного host(s), використовуючи призначені credentials. Також можна використовувати це для виконання конкретної команди на віддалених host через SSH або для SCP файлів.
- `link_tcp`: Зв’язати з іншим agent через TCP, дозволяючи прямий зв’язок між agents.
- `link_webshell`: Зв’язати з agent, використовуючи webshell P2P profile, дозволяючи віддалений доступ до web interface агента.
- `rpfwd`: Запустити або зупинити Reverse Port Forward, дозволяючи віддалений доступ до services у цільовій network.
- `socks`: Запустити або зупинити SOCKS5 proxy у цільовій network, дозволяючи тунелювання traffic через compromised host. Сумісно з tools на кшталт proxychains.
- `portscan`: Сканувати host(s) на відкриті ports, корисно для виявлення потенційних targets для lateral movement або подальших attacks.

### Process execution

- `shell`: Виконати одну shell command через /bin/sh, дозволяючи пряме виконання commands на цільовій системі.
- `run`: Виконати command з диска з arguments, дозволяючи запуск binaries або scripts на цільовій системі.
- `pty`: Відкрити інтерактивний PTY, дозволяючи прямий interaction з shell на цільовій системі.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
