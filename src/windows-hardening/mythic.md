# Mythic

{{#include ../banners/hacktricks-training.md}}

## Що таке Mythic?

Mythic — це open-source, модульний, колаборативний framework command and control (C2), створений для red teaming. Він дає операторам змогу керувати та розгортати agents (payloads) на різних операційних системах, зокрема Windows, Linux і macOS. Mythic надає browser UI для tasking з кількома операторами, обробки файлів, керування SOCKS/rpfwd і генерації payload.

На відміну від монолітних framework, сам репозиторій Mythic **не** постачається з payload types або C2 profiles. Agents, wrappers і C2 profiles зазвичай встановлюються як зовнішні компоненти й можуть оновлюватися незалежно від core Mythic.

### Встановлення

Щоб встановити Mythic, дотримуйтеся інструкцій в офіційному **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Типовий bootstrap із директорії Mythic такий:
```bash
sudo make
sudo ./mythic-cli start
```
Якщо Mythic вже запущено, зазвичай можна додати новий agent або profile за допомогою `./mythic-cli install github ...`, а потім або перезапустити Mythic, або просто запустити новий компонент напряму.

### Agents

Mythic підтримує кілька agents, які є **payloads, що виконують tasks на compromised systems**. Кожен agent можна налаштувати під конкретні потреби, і він може працювати на різних operating systems.

За замовчуванням Mythic не має встановлених agents. Open-source community agents розміщені в [**https://github.com/MythicAgents**](https://github.com/MythicAgents), а [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) корисна, щоб швидко перевірити supported operating systems, payload formats, wrappers, and C2 profiles.

Щоб встановити agent із цієї org, ви можете виконати:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Форма `sudo -E` корисна, коли ви встановлюєте з не-root середовища. Ви можете додавати нових агентів за допомогою попередньої команди, навіть якщо Mythic уже запущено.

### C2 Profiles

C2 profiles у Mythic визначають **how agents communicate with the Mythic server**. Вони вказують communication protocol, encryption methods та інші налаштування. Ви можете створювати та керувати C2 profiles через Mythic web interface.

By default Mythic is installed with no profiles, however, it's possible to download some profiles from the repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) running:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

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
### Current build/profile notes

- Apollo can currently emit `WinExe`, `Shellcode`, `Service`, and `Source` payloads.
- The commonly used Apollo profiles are `http`, `httpx`, `smb`, `tcp`, and `websocket`.
- `httpx` is usually the more flexible option when you need domain rotation, proxy support, custom message placement, and message transforms instead of the older static `http` profile.
- Apollo supports wrapper payloads such as `service_wrapper` and `scarecrow_wrapper`.
- `register_file` and `register_assembly` are the staging primitives for `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, and `powerpick`. In current Apollo builds, those staged artifacts are cached client-side as DPAPI-protected AES256 blobs.
- `ls` and `ps` results integrate especially well with Mythic's browser scripts and file/process browser, which makes operator triage noticeably faster in collaborative operations.

This agent has a lot of commands that makes it very similar to Cobalt Strike's Beacon with some extras. Among them, it supports:

### Common actions

- `cat`: Вивести вміст файла
- `cd`: Змінити поточний робочий каталог
- `cp`: Скопіювати файл з одного місця в інше
- `ls`: Перелічити файли та каталоги в поточному каталозі або вказаному шляху
- `ifconfig`: Отримати мережеві адаптери та інтерфейси
- `netstat`: Отримати інформацію про TCP і UDP-з'єднання
- `pwd`: Вивести поточний робочий каталог
- `ps`: Перелічити запущені процеси в цільовій системі (з додатковою інформацією)
- `jobs`: Перелічити всі активні jobs, пов'язані з довготривалими tasking
- `download`: Завантажити файл із цільової системи на локальну машину
- `upload`: Завантажити файл із локальної машини на цільову систему
- `reg_query`: Запитати ключі та значення реєстру в цільовій системі
- `reg_write_value`: Записати нове значення в указаний ключ реєстру
- `sleep`: Змінити інтервал sleep агента, який визначає, як часто він зв'язується з сервером Mythic
- And many others, use `help` to see the full list of available commands.

### Privilege escalation

- `getprivs`: Увімкнути якомога більше привілеїв у поточному токені потоку
- `getsystem`: Відкрити handle до winlogon і продублювати токен, фактично підвищивши привілеї до рівня SYSTEM
- `make_token`: Створити нову logon session і застосувати її до агента, що дає змогу impersonation іншого користувача
- `steal_token`: Викрасти primary token з іншого процесу, що дає змогу агенту impersonate користувача цього процесу
- `pth`: Pass-the-Hash attack, що дає змогу агенту автентифікуватися як користувач, використовуючи його NTLM hash без потреби в plaintext password
- `mimikatz`: Запустити команди Mimikatz для вилучення credentials, hashes та іншої чутливої інформації з memory або SAM database
- `rev2self`: Повернути токен агента до його primary token, фактично скинувши привілеї назад до початкового рівня
- `ppid`: Змінити parent process для post-exploitation jobs, указавши новий parent process ID, що дає кращий контроль над execution context job
- `printspoofer`: Виконати команди PrintSpoofer, щоб обійти security measures spooler'а друку, що дає змогу підвищити привілеї або виконати code execution
- `dcsync`: Синхронізувати Kerberos keys користувача на локальну машину, що дає змогу offline password cracking або подальші attacks
- `ticket_cache_add`: Додати Kerberos ticket до поточної logon session або вказаної, що дає змогу повторно використовувати ticket або impersonation

### Process execution

- `assembly_inject`: Дозволяє inject .NET assembly loader у віддалений процес
- `blockdlls`: Блокувати завантаження DLL, підписаних не Microsoft, у post-exploitation jobs
- `execute_assembly`: Виконує .NET assembly у контексті агента
- `execute_coff`: Виконує COFF file у memory, що дає змогу in-memory execution скомпільованого коду
- `execute_pe`: Виконує unmanaged executable (PE)
- `get_injection_techniques`: Показати доступні techniques injection і поточну вибрану
- `inline_assembly`: Виконує .NET assembly у disposable AppDomain, що дає змогу тимчасово виконати code без впливу на основний процес агента
- `register_assembly`: Зареєструвати .NET assembly для подальшого виконання
- `register_file`: Зареєструвати файл у кеші агента для подальшого `execute_*` або PowerShell tasking
- `run`: Виконує binary у цільовій системі, використовуючи PATH системи для пошуку executable
- `set_injection_technique`: Змінити injection primitive, який використовують post-exploitation jobs
- `shinject`: Injects shellcode у віддалений процес, що дає змогу in-memory execution довільного коду
- `inject`: Injects agent shellcode у віддалений процес, що дає змогу in-memory execution коду агента
- `spawn`: Створює нову agent session у вказаному executable, що дає змогу виконувати shellcode в новому процесі
- `spawnto_x64` and `spawnto_x86`: Змінити стандартний binary, який використовують post-exploitation jobs, на вказаний шлях замість використання `rundll32.exe` без параметрів, що дуже шумно.

### Mythic Forge

Це дає змогу **load COFF/BOF** files з Mythic Forge, який є репозиторієм pre-compiled payloads і tools, що можуть бути executed на цільовій системі. З усіма commands, які можна завантажити, буде можливо виконувати common actions, запускаючи їх у поточному process агента як BOFs (зазвичай із кращим OPSEC, ніж spawning окремого process).

Start installing them with:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, use `forge_collections` to show the COFF/BOF modules from the Mythic Forge to be able to select and load them into the agent's memory for execution. By default, the following 2 collections are added in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

After one module is loaded, it'll appear in the list as another command like `forge_bof_sa-whoami` or `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Імпортує новий PowerShell script (.ps1) у кеш агента для подальшого виконання
- `powershell`: Виконує команду PowerShell у контексті агента, дозволяючи розширене scripting та automation
- `powerpick`: Injects a PowerShell loader assembly into a sacrificial process and executes a PowerShell command (without powershell logging).
- `psinject`: Виконує PowerShell у вказаному process, забезпечуючи цільове виконання scripts у контексті іншого process
- `shell`: Виконує shell command у контексті агента, подібно до запуску команди в cmd.exe

### Lateral Movement

- `jump_psexec`: Використовує техніку PsExec для lateral movement на новий host шляхом попереднього копіювання executable агента Apollo (apollo.exe) і його запуску.
- `jump_wmi`: Використовує техніку WMI для lateral movement на новий host шляхом попереднього копіювання executable агента Apollo (apollo.exe) і його запуску.
- `link` and `unlink`: Create and tear down P2P links (for example over SMB/TCP) between callbacks.
- `wmiexecute`: Виконує command на локальній або вказаній remote system за допомогою WMI, з необов’язковими credentials для impersonation.
- `net_dclist`: Отримує список domain controllers для вказаного domain, корисно для визначення потенційних targets для lateral movement.
- `net_localgroup`: Перелічує local groups на вказаному computer, за замовчуванням localhost, якщо computer не вказано.
- `net_localgroup_member`: Отримує membership локальної групи для вказаної group на локальному або remote computer, дозволяючи enumeration користувачів у певних groups.
- `net_shares`: Перелічує remote shares та їх доступність на вказаному computer, корисно для визначення потенційних targets для lateral movement.
- `socks`: Увімкнює SOCKS 5 compliant proxy у target network, дозволяючи tunneling traffic через compromised host. Compatible with tools like proxychains.
- `rpfwd`: Запускає listening на вказаному port на target host і forward-ить traffic через Mythic до remote IP та port, дозволяючи remote access до services на target network.
- `listpipes`: Перелічує всі named pipes на локальній system, що може бути корисно для lateral movement або privilege escalation шляхом взаємодії з IPC mechanisms.

For the lower-level WMI execution primitives used underneath `jump_wmi` or `wmiexecute`, check [WmiExec](lateral-movement/wmiexec.md). For broader pivoting patterns, check [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Відображає детальну інформацію про конкретні commands або загальну інформацію про всі available commands в agent.
- `clear`: Позначає tasks як 'cleared', щоб agents не могли їх підібрати. Ви можете вказати `all`, щоб очистити всі tasks, або `task Num`, щоб очистити конкретну task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is a Golang agent that compiles into **Linux and macOS** executables.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Поточні примітки щодо build/profile

- Поточні builds Poseidon target Linux і macOS на `x86_64` та `arm64`.
- Підтримувані формати output включають native executables плюс outputs у стилі shared-library, такі як `dylib` і `so`.
- Poseidon підтримує `http`, `websocket`, `tcp`, і `dynamichttp`, а поточні builders expose multi-egress settings, такі як `egress_order` і failover thresholds.
- Build-time options, такі як `proxy_bypass` і `garble`, варто перевірити, коли вам потрібна або cleaner network behavior, або додаткова Go binary obfuscation.

Для macOS-specific tradecraft навколо Mythic-backed operations, JAMF abuse, або ідей MDM-as-C2, дивіться [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Коли використовується на Linux або macOS, він має деякі цікаві commands:

### Common actions

- `cat`: Вивести вміст файлу
- `cd`: Змінити поточний working directory
- `chmod`: Змінити permissions файлу
- `config`: Переглянути поточний config і host information
- `cp`: Скопіювати файл з одного місця в інше
- `curl`: Виконати один web request з optional headers і method
- `upload`: Завантажити файл на target
- `download`: Завантажити файл із target system на local machine
- І багато іншого

### Search Sensitive Information

- `triagedirectory`: Знайти цікаві файли в межах directory на host, такі як sensitive files або credentials.
- `getenv`: Отримати всі поточні environment variables.

### Move laterally

- `ssh`: SSH до host, використовуючи designated credentials, і відкрити PTY без запуску ssh.
- `sshauth`: SSH до вказаного host(ів), використовуючи designated credentials. Ви також можете використати це для виконання певної команди на remote hosts через SSH або для SCP файлів.
- `link_tcp`: Зв’язатися з іншим agent через TCP, що дозволяє direct communication між agents.
- `link_webshell`: Зв’язатися з agent, використовуючи webshell P2P profile, що дозволяє remote access до web interface agent’а.
- `rpfwd`: Запустити або зупинити Reverse Port Forward, що дозволяє remote access до services у target network.
- `socks`: Запустити або зупинити SOCKS5 proxy у target network, що дозволяє tunneling traffic через compromised host. Compatible з tools like proxychains.
- `portscan`: Сканувати host(и) на open ports, корисно для identification potential targets для lateral movement або подальших attacks.

### Process execution

- `shell`: Виконати одну shell command через /bin/sh, що дозволяє direct execution commands на target system.
- `run`: Виконати command з disk з arguments, що дозволяє запуск binaries або scripts на target system.
- `pty`: Відкрити interactive PTY, що дозволяє direct interaction with the shell на target system.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
