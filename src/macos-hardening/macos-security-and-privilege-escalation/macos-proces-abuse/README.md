# Zloupotreba macOS procesa

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o procesima

Proces je instanca izvršnog programa koji se izvršava, međutim, procese ne izvršavaju code, već thread-ovi. Zato su **procesi samo kontejneri za pokrenute thread-ove** koji obezbeđuju memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su se pokretali unutar drugih procesa (osim PID-a 1) pozivanjem **`fork`** funkcije, koja bi kreirala identičnu kopiju trenutnog procesa, nakon čega bi **child process** uglavnom pozvao **`execve`** da učita novi izvršni program i pokrene ga. Zatim je uveden **`vfork`** kako bi se ovaj proces ubrzao bez kopiranja memorije.\
Nakon toga je uveden **`posix_spawn`**, koji kombinuje **`vfork`** i **`execve`** u jednom pozivu i prihvata flag-ove:

- `POSIX_SPAWN_RESETIDS`: Resetuje effective id vrednosti na real id vrednosti
- `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost process group-i
- `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signal-a
- `POSIX_SPAWN_SETSIGMASK`: Postavlja signal masku
- `POSIX_SPAWN_SETEXEC`: Izvršava se u istom procesu (kao `execve`, uz više opcija)
- `POSIX_SPAWN_START_SUSPENDED`: Pokreće se suspendovan
- `_POSIX_SPAWN_DISABLE_ASLR`: Pokreće se bez ASLR-a
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoljava `rwx` nad data segmentima
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Podrazumevano zatvara sve file description-e pri exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizuje visoke bitove ASLR slide-a

Pored toga, `posix_spawn` prihvata **`posix_spawnattr`** podešavanja koja kontrolišu aspekte pokrenutog procesa i **`posix_spawn_file_actions`** stavke koje menjaju file descriptor-e.

Kada proces umre, on šalje **return code parent procesu** (ako je parent umro, novi parent je PID 1) pomoću signala `SIGCHLD`. Parent mora da preuzme ovu vrednost pozivanjem `wait4()` ili `waitid()`, a do tada child ostaje u zombie stanju, gde je i dalje naveden, ali ne troši resurse.

### PIDs

PIDs, odnosno process identifiers, identifikuju jedinstveni proces. U XNU-u, **PIDs** su 64-bitni, monotono se povećavaju i **nikada se ne vraćaju na početak** (kako bi se sprečile zloupotrebe).

### Process Groups, Sessions i Coalations

**Procesi** mogu biti organizovani u **groups** kako bi se njima lakše upravljalo. Na primer, komande u shell script-u biće u istoj process group-i, pa je moguće **signalizirati ih zajedno**, na primer pomoću kill-a.\
Takođe je moguće **grupisati procese u sessions**. Kada proces pokrene session (`setsid(2)`), child procesi se smeštaju u tu session, osim ako ne pokrenu sopstvenu session.

Coalition je još jedan način grupisanja procesa u Darwin-u. Pristupanje procesa coalition-u omogućava mu pristup pool resursima, deljenje ledger-a ili izlaganje Jetsam-u. Coalitions imaju različite uloge: Leader, XPC service, Extension.

### Credentials i Personae

Svaki proces poseduje **credentials** koje **identifikuju njegove privilegije** u sistemu. Svaki proces ima jedan primarni `uid` i jedan primarni `gid` (iako može pripadati većem broju grupa).\
Takođe je moguće promeniti user i group id ako binary ima `setuid/setgid` bit.\
Postoji nekoliko funkcija za **postavljanje novih uid/gid vrednosti**.

Syscall **`persona`** obezbeđuje alternativni skup **credentials**. Usvajanje personae podrazumeva istovremeno preuzimanje njenog uid-a, gid-a i članstva u grupama. U [**source code-u**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći struct:
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
## Osnovne informacije o thread-ovima

1. **POSIX Threads (pthreads):** macOS podržava POSIX thread-ove (`pthreads`), koji su deo standardnog threading API-ja za C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, a potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža neophodne funkcije za kreiranje i upravljanje thread-ovima.
2. **Kreiranje thread-ova:** Funkcija `pthread_create()` koristi se za kreiranje novih thread-ova. Interno, ova funkcija poziva `bsdthread_create()`, što je system call nižeg nivoa specifičan za XNU kernel (kernel na kojem je macOS zasnovan). Ovaj system call prihvata različite flag-ove izvedene iz `pthread_attr` (atributa), koji definišu ponašanje thread-a, uključujući politike raspoređivanja i veličinu steka.
- **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove thread-ove iznosi 512 KB, što je dovoljno za uobičajene operacije, ali se može prilagoditi pomoću atributa thread-a ako je potrebno više ili manje prostora.
3. **Inicijalizacija thread-a:** Funkcija `__pthread_init()` ključna je tokom podešavanja thread-a i koristi argument `env[]` za parsiranje environment varijabli, koje mogu sadržati informacije o lokaciji i veličini steka.

#### Terminacija thread-ova u macOS-u

1. **Izlazak iz thread-ova:** Thread-ovi se obično terminiraju pozivanjem funkcije `pthread_exit()`. Ova funkcija omogućava thread-u da se uredno završi, obavi neophodno čišćenje i pošalje povratnu vrednost thread-ovima koji čekaju na njegovo završavanje.
2. **Čišćenje thread-a:** Nakon pozivanja funkcije `pthread_exit()`, poziva se funkcija `pthread_terminate()`, koja uklanja sve povezane strukture thread-a. Ona dealocira Mach thread port-ove (Mach je komunikacioni podsistem u XNU kernelu) i poziva `bsdthread_terminate`, syscall koji uklanja strukture na nivou kernela povezane sa thread-om.

#### Mehanizmi sinhronizacije

Za upravljanje pristupom deljenim resursima i izbegavanje race condition-a, macOS pruža nekoliko primitiva za sinhronizaciju. Oni su ključni u multi-threading okruženjima kako bi se obezbedili integritet podataka i stabilnost sistema:

1. **Mutex-i:**
- **Regularni mutex (Signature: 0x4D555458):** Standardni mutex memorijskog otiska od 60 bajtova (56 bajtova za mutex i 4 bajta za signature).
- **Fast mutex (Signature: 0x4d55545A):** Sličan regularnom mutex-u, ali optimizovan za brže operacije; takođe zauzima 60 bajtova.
2. **Condition Variables:**
- Koriste se za čekanje da nastupe određeni uslovi, a veličina im je 44 bajta (40 bajtova plus 4-bajtni signature).
- **Atributi Condition Variable-a (Signature: 0x434e4441):** Konfiguracioni atributi za condition variable-e, veličine 12 bajtova.
3. **Once Variable (Signature: 0x4f4e4345):**
- Obezbeđuje da se deo inicijalizacionog koda izvrši samo jednom. Njegova veličina iznosi 12 bajtova.
4. **Read-Write Locks:**
- Omogućavaju više čitača ili jednog upisivača u datom trenutku, čime se omogućava efikasan pristup deljenim podacima.
- **Read Write Lock (Signature: 0x52574c4b):** Veličine 196 bajtova.
- **Atributi Read Write Lock-a (Signature: 0x52574c41):** Atributi za read-write lock-ove, veličine 20 bajtova.

> [!TIP]
> Poslednja 4 bajta ovih objekata koriste se za otkrivanje overflow-a.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** u kontekstu Mach-O fajlova (formata za izvršne fajlove u macOS-u) koriste se za deklarisanje promenljivih koje su specifične za **svaki thread** u multi-threaded aplikaciji. Time se obezbeđuje da svaki thread ima sopstvenu, odvojenu instancu promenljive, što omogućava izbegavanje konflikata i očuvanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije, kao što su mutex-i.

U jeziku C i srodnim jezicima, thread-local promenljivu možete deklarisati pomoću ključne reči **`__thread`**. Evo kako to funkcioniše u vašem primeru:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
This snippet defines `tlv_var` as a thread-local variable. Each thread running this code will have its own `tlv_var`, and changes one thread makes to `tlv_var` will not affect `tlv_var` in another thread.

In the Mach-O binary, the data related to thread local variables is organized into specific sections:

- **`__DATA.__thread_vars`**: This section contains the metadata about the thread-local variables, like their types and initialization status.
- **`__DATA.__thread_bss`**: This section is used for thread-local variables that are not explicitly initialized. It's a part of memory set aside for zero-initialized data.

Mach-O also provides a specific API called **`tlv_atexit`** to manage thread-local variables when a thread exits. This API allows you to **register destructors**—special functions that clean up thread-local data when a thread terminates.

### Threading Priorities

Understanding thread priorities involves looking at how the operating system decides which threads to run and when. This decision is influenced by the priority level assigned to each thread. In macOS and Unix-like systems, this is handled using concepts like `nice`, `renice`, and Quality of Service (QoS) classes.

#### Nice and Renice

1. **Nice:**
- The `nice` value of a process is a number that affects its priority. Every process has a nice value ranging from -20 (the highest priority) to 19 (the lowest priority). The default nice value when a process is created is typically 0.
- A lower nice value (closer to -20) makes a process more "selfish," giving it more CPU time compared to other processes with higher nice values.
2. **Renice:**
- `renice` is a command used to change the nice value of an already running process. This can be used to dynamically adjust the priority of processes, either increasing or decreasing their CPU time allocation based on new nice values.
- For example, if a process needs more CPU resources temporarily, you might lower its nice value using `renice`.

#### Quality of Service (QoS) Classes

QoS classes are a more modern approach to handling thread priorities, particularly in systems like macOS that support **Grand Central Dispatch (GCD)**. QoS classes allow developers to **categorize** work into different levels based on their importance or urgency. macOS manages thread prioritization automatically based on these QoS classes:

1. **User Interactive:**
- This class is for tasks that are currently interacting with the user or require immediate results to provide a good user experience. These tasks are given the highest priority to keep the interface responsive (e.g., animations or event handling).
2. **User Initiated:**
- Tasks that the user initiates and expects immediate results, such as opening a document or clicking a button that requires computations. These are high priority but below user interactive.
3. **Utility:**
- These tasks are long-running and typically show a progress indicator (e.g., downloading files, importing data). They are lower in priority than user-initiated tasks and do not need to finish immediately.
4. **Background:**
- This class is for tasks that operate in the background and are not visible to the user. These can be tasks like indexing, syncing, or backups. They have the lowest priority and minimal impact on system performance.

Using QoS classes, developers do not need to manage the exact priority numbers but rather focus on the nature of the task, and the system optimizes the CPU resources accordingly.

Moreover, there are different **thread scheduling policies** that flows to specify a set of scheduling parameters that the scheduler will take into consideration. This can be done using `thread_policy_[set/get]`. This might be useful in race condition attacks.

## macOS Process Abuse

macOS provides many mechanisms for **processes to interact, communicate, and share data**. Although these mechanisms are essential to normal system operation, attackers can abuse them for injection, code execution, or data access.

### Library Injection

Library Injection is a technique wherein an attacker **forces a process to load a malicious library**. Once injected, the library runs in the context of the target process, providing the attacker with the same permissions and access as the process.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking involves **intercepting function calls** or messages within a software code. By hooking functions, an attacker can **modify the behavior** of a process, observe sensitive data, or even gain control over the execution flow.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) refers to different methods by which separate processes **share and exchange data**. While IPC is fundamental for many legitimate applications, it can also be misused to subvert process isolation, leak sensitive information, or perform unauthorized actions.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications executed with specific env variables could be vulnerable to process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

It's possible to use the flags `--load-extension` and `--use-fake-ui-for-media-stream` to perform a **man in the browser attack** allowing to steal keystrokes, traffic, cookies, inject scripts in pages...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **define user interface (UI) elements** and their interactions within an application. However, they can **execute arbitrary commands** and **Gatekeeper doesn't stop** an already executed application from being executed if a **NIB file is modified**. Therefore, they could be used to make arbitrary programs execute arbitrary commands:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

It's possible to inject JVM options through **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, or **`JDK_JAVA_OPTIONS`** and load a Java or native agent before the application starts.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

It's possible to inject code into .NET applications through **`DOTNET_STARTUP_HOOKS`** before `Main`, or by abusing the .NET debugging functionality when its prerequisites are present.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash reads **`BASH_ENV`**; zsh reads **`$ZDOTDIR/.zshenv`**; and fish reads configuration below **`XDG_CONFIG_HOME`** or **`XDG_DATA_DIRS`**. Each can execute a controlled startup file before the intended command:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** or **`PHP_INI_SCAN_DIR`** can load controlled PHP configuration whose **`auto_prepend_file`** executes before the target script.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

The standalone Lua interpreter executes code or an `@file` from **`LUA_INIT`** (or its version-specific variant) before processing the target script.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** and **`R_PROFILE`** redirect startup profiles containing R code. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** plus an R library path can instead auto-load an installed package.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redirects the depot whose `config/startup.jl` is automatically executed.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`**, or **`ERL_ZFLAGS`** can inject an Erlang VM **`-eval`** expression without requiring a payload file; Elixir workloads commonly start the same VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** and **`OCTAVE_VERSION_INITFILE`** redirect Octave startup scripts.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

On macOS and Linux, **`XDG_CONFIG_HOME`** can redirect PowerShell user profiles that execute when `pwsh` starts.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Check different options to make a Perl script execute arbitrary code in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

I't also possible to abuse ruby env variables to make arbitrary scripts execute arbitrary code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

The **`PYTHONWARNINGS`** and **`BROWSER`** standard-library chain can execute a command during warning-filter parsing. A file-backed alternative places `sitecustomize.py` on **`PYTHONPATH`** so normal `site` initialization imports it before the target script. Interactive-only variables such as **`PYTHONSTARTUP`** have narrower applicability.

Note that executables compiled with **`pyinstaller`** won't use these environmental variables even if they are running using an embedded python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

Separately, Homebrew commonly installs Python below `/opt/homebrew`, where members of the local `admin` group may be able to replace the launcher. That is a writable-binary hijack rather than environment-variable injection; verify ownership and ACLs before treating it as exploitable.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is an open-source **EndpointSecurity**-based application that detects and blocks process injection. It is a good reference for which signals are observable through Endpoint Security, since it alerts on:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** on process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` and `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** calls — one process asking for another's task port, which is the prerequisite for injecting into it.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` and `--remote-debugging-port`, which start an Electron app in debug mode and let anyone attach and run code in it.<sup>[[3]](#references)</sup>
- **Symlink/hardlink creation across privilege levels** — the classic "plant a link as a normal user, point it at a privileged location" primitive. Note that **symlinks can be alerted on but not blocked**: EndpointSecurity does not expose the link destination before creation.

### Calls made by other processes

In [**this blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) you can find how it's possible to use the function **`task_name_for_pid`** to get information about other **processes injecting code in a process** and then getting information about that other process.<sup>[[4]](#references)</sup>

Note that to call that function you need to be **the same uid** as the one running the process or **root** (and it returns info about the process, not a way to inject code).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
