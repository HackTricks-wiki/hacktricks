# Abuse ya Processes za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi kuhusu Processes

Process ni mfano wa executable inayotekelezwa, hata hivyo processes hazitekelezi code; threads ndizo hufanya hivyo. Kwa hiyo **processes ni containers tu za threads zinazotekelezwa**, zikitoa memory, descriptors, ports, permissions...

Kijadi, processes zilianzishwa ndani ya processes nyingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala halisi ya process ya sasa, kisha **child process** kwa kawaida ingaita **`execve`** ili kupakia executable mpya na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kufanya process hii iwe ya haraka zaidi bila kunakili memory.\
Kisha **`posix_spawn`** ilianzishwa, ikiunganisha **`vfork`** na **`execve`** katika call moja na kukubali flags:

- `POSIX_SPAWN_RESETIDS`: Weka upya effective ids ziwe real ids
- `POSIX_SPAWN_SETPGROUP`: Weka process group affiliation
- `POSUX_SPAWN_SETSIGDEF`: Weka signal default behaviour
- `POSIX_SPAWN_SETSIGMASK`: Weka signal mask
- `POSIX_SPAWN_SETEXEC`: Fanya Exec katika process hiyo hiyo (kama `execve` yenye options zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anza ikiwa suspended
- `_POSIX_SPAWN_DISABLE_ASLR`: Anza bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga file descriptions zote kwenye exec(2) kwa default
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomize high bits za ASLR slide

Zaidi ya hayo, `posix_spawn` hukubali settings za **`posix_spawnattr`** zinazodhibiti vipengele vya process iliyoanzishwa, pamoja na entries za **`posix_spawn_file_actions`** zinazorekebisha file descriptors.

Process inapokufa, hutuma **return code kwa parent process** (ikiwa parent alikufa, parent mpya huwa PID 1) kwa signal `SIGCHLD`. Parent anahitaji kupata thamani hii kwa kuita `wait4()` au `waitid()`, na hadi hilo litokee child hubaki katika hali ya zombie, ambapo bado imeorodheshwa lakini haitumii resources.

### PIDs

PIDs, au process identifiers, hutambua process ya kipekee. Katika XNU, **PIDs** zina ukubwa wa **64bits**, huongezeka kwa mpangilio na **hazijawahi kuzunguka** (ili kuzuia abuses).

### Process Groups, Sessions & Coalations

**Processes** zinaweza kuwekwa katika **groups** ili kurahisisha kuzishughulikia. Kwa mfano, commands katika shell script zitakuwa katika process group moja, hivyo inawezekana **kuzitumia signal pamoja** kwa kutumia kill, kwa mfano.\
Pia inawezekana **kuweka processes katika sessions**. Process inapoanzisha session (`setsid(2)`), child processes huwekwa ndani ya session hiyo, isipokuwa zianzishe session yao wenyewe.

Coalition ni njia nyingine ya ku-group processes katika Darwin. Process inapojiunga na coalition, huweza kufikia pool resources, kushiriki ledger au kukabiliwa na Jetsam. Coalations zina roles tofauti: Leader, XPC service, Extension.

### Credentials & Personae

Kila process hushikilia **credentials** zinazo **tambua privileges zake** katika mfumo. Kila process itakuwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa inaweza kuwa katika groups kadhaa).\
Pia inawezekana kubadilisha user na group id ikiwa binary ina bit ya `setuid/setgid`.\
Kuna functions kadhaa za **kuweka uids/gids mpya**.

Syscall **`persona`** hutoa seti **mbadala ya credentials**. Kupitisha persona huchukua uid, gid na group memberships zake **kwa wakati mmoja**. Katika [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:
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
## Maelezo ya Msingi kuhusu Threads

1. **POSIX Threads (pthreads):** macOS inasaidia POSIX threads (`pthreads`), ambazo ni sehemu ya standard threading API ya C/C++. Utekelezaji wa pthreads katika macOS unapatikana kwenye `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatokana na project ya `libpthread` inayopatikana hadharani. Library hii hutoa functions zinazohitajika kuunda na kudhibiti threads.
2. **Creating Threads:** Function ya `pthread_create()` hutumika kuunda threads mpya. Kwa ndani, function hii huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini mahususi kwa XNU kernel (kernel ambayo macOS imejengwa juu yake). System call hii hupokea flags mbalimbali zinazotokana na `pthread_attr` (attributes) zinazoeleza tabia ya thread, ikiwa ni pamoja na scheduling policies na stack size.
- **Default Stack Size:** Default stack size ya threads mpya ni 512 KB, ambayo inatosha kwa operations za kawaida lakini inaweza kurekebishwa kupitia thread attributes ikiwa nafasi zaidi au kidogo inahitajika.
3. **Thread Initialization:** Function ya `__pthread_init()` ni muhimu wakati wa kusanidi thread, ikitumia argument ya `env[]` kuchanganua environment variables ambazo zinaweza kujumuisha maelezo kuhusu eneo na size ya stack.

#### Thread Termination katika macOS

1. **Exiting Threads:** Kwa kawaida threads husitishwa kwa kuita `pthread_exit()`. Function hii huwezesha thread kutoka kwa usafi, ikifanya cleanup inayohitajika na kuruhusu thread kutuma return value kwa joiners wowote.
2. **Thread Cleanup:** Baada ya kuita `pthread_exit()`, function ya `pthread_terminate()` huitwa; function hii hushughulikia kuondoa thread structures zote zinazohusiana. Hutoa Mach thread ports (Mach ni communication subsystem katika XNU kernel) na huita `bsdthread_terminate`, syscall inayoondoa kernel-level structures zinazohusiana na thread.

#### Synchronization Mechanisms

Ili kudhibiti ufikiaji wa shared resources na kuepuka race conditions, macOS hutoa synchronization primitives kadhaa. Hizi ni muhimu katika multi-threading environments ili kuhakikisha data integrity na system stability:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Mutex ya kawaida yenye memory footprint ya bytes 60 (bytes 56 kwa mutex na bytes 4 kwa signature).
- **Fast Mutex (Signature: 0x4d55545A):** Inafanana na regular mutex lakini imeboreshwa kwa operations za haraka zaidi, pia ikiwa na size ya bytes 60.
2. **Condition Variables:**
- Hutumika kusubiri conditions fulani zitokee, ikiwa na size ya bytes 44 (bytes 40 pamoja na signature ya bytes 4).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes za condition variables, zikiwa na size ya bytes 12.
3. **Once Variable (Signature: 0x4f4e4345):**
- Huhakikisha kwamba kipande cha initialization code kinatekelezwa mara moja pekee. Size yake ni bytes 12.
4. **Read-Write Locks:**
- Huruhusu readers wengi au writer mmoja kwa wakati mmoja, na hivyo kuwezesha ufikiaji bora wa shared data.
- **Read Write Lock (Signature: 0x52574c4b):** Ina size ya bytes 196.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes za read-write locks, zikiwa na size ya bytes 20.

> [!TIP]
> Bytes 4 za mwisho za objects hizo hutumika kutambua overflows.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** katika muktadha wa files za Mach-O (format ya executables katika macOS) hutumika kutangaza variables ambazo ni mahususi kwa **kila thread** katika multi-threaded application. Hii huhakikisha kwamba kila thread ina instance yake tofauti ya variable, na kutoa njia ya kuepuka conflicts na kudumisha data integrity bila kuhitaji synchronization mechanisms za wazi kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza thread-local variable kwa kutumia keyword ya **`__thread`**. Hivi ndivyo inavyofanya kazi katika mfano wako:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Kipande hiki kinafafanua `tlv_var` kama variable ya thread-local. Kila thread inayoendesha code hii itakuwa na `tlv_var` yake, na mabadiliko yanayofanywa na thread moja kwenye `tlv_var` hayataathiri `tlv_var` katika thread nyingine.

Katika binary ya Mach-O, data inayohusiana na variables za thread-local imepangwa katika sections maalum:

- **`__DATA.__thread_vars`**: Section hii ina metadata kuhusu variables za thread-local, kama vile aina zake na hali ya initialization.
- **`__DATA.__thread_bss`**: Section hii hutumika kwa variables za thread-local ambazo hazija-initialize waziwazi. Ni sehemu ya memory iliyotengwa kwa data iliyo-initialize kwa zero.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ya kusimamia variables za thread-local thread inapotoka. API hii inaruhusu **kusajili destructors**—functions maalum zinazofanya cleanup ya data ya thread-local thread inapomalizika.

### Threading Priorities

Kuelewa thread priorities kunahusisha kuangalia jinsi operating system huamua ni threads zipi ziendeshwe na wakati gani. Uamuzi huu huathiriwa na priority level iliyopewa kila thread. Katika macOS na systems zinazofanana na Unix, hili hushughulikiwa kwa kutumia dhana kama `nice`, `renice`, na Quality of Service (QoS) classes.

#### Nice na Renice

1. **Nice:**
- Thamani ya `nice` ya process ni nambari inayoathiri priority yake. Kila process ina nice value kuanzia -20 (priority ya juu zaidi) hadi 19 (priority ya chini zaidi). Nice value ya default process inapoundwa kwa kawaida ni 0.
- Nice value ya chini (iliyo karibu na -20) hufanya process iwe "selfish" zaidi, ikiipa CPU time zaidi ikilinganishwa na processes nyingine zenye nice values za juu.
2. **Renice:**
- `renice` ni command inayotumika kubadilisha nice value ya process ambayo tayari inaendelea. Hii inaweza kutumika kurekebisha priority ya processes kwa wakati huo, kwa kuongeza au kupunguza mgao wao wa CPU time kulingana na nice values mpya.
- Kwa mfano, ikiwa process inahitaji CPU resources zaidi kwa muda, unaweza kupunguza nice value yake kwa kutumia `renice`.

#### Quality of Service (QoS) Classes

QoS classes ni mbinu ya kisasa zaidi ya kushughulikia thread priorities, hasa katika systems kama macOS zinazotumia **Grand Central Dispatch (GCD)**. QoS classes huwawezesha developers **kuainisha** kazi katika levels tofauti kulingana na umuhimu au uharaka wake. macOS husimamia thread prioritization automatically kulingana na QoS classes hizi:

1. **User Interactive:**
- Class hii ni ya tasks zinazoingiliana na user kwa wakati huo au zinazohitaji matokeo ya haraka ili kutoa user experience nzuri. Tasks hizi hupewa priority ya juu zaidi ili interface ibaki responsive (kwa mfano, animations au event handling).
2. **User Initiated:**
- Tasks zinazoanzishwa na user na ambazo anatarajia matokeo ya haraka, kama kufungua document au kubofya button inayohitaji computations. Hizi zina priority ya juu lakini iko chini ya user interactive.
3. **Utility:**
- Tasks hizi hudumu kwa muda mrefu na kwa kawaida huonyesha progress indicator (kwa mfano, kupakua files au ku-import data). Zina priority ya chini kuliko tasks zilizoanzishwa na user na hazihitaji kumalizika mara moja.
4. **Background:**
- Class hii ni ya tasks zinazofanya kazi background na hazionekani kwa user. Hizi zinaweza kuwa tasks kama indexing, syncing, au backups. Zina priority ya chini zaidi na athari ndogo kwenye performance ya system.

Kwa kutumia QoS classes, developers hawahitaji kusimamia nambari kamili za priority, bali huzingatia aina ya task, na system huboresha CPU resources ipasavyo.

Zaidi ya hayo, kuna **thread scheduling policies** tofauti zinazowezesha kubainisha seti ya scheduling parameters ambazo scheduler itazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hii inaweza kuwa muhimu katika race condition attacks.

## macOS Process Abuse

macOS hutoa mechanisms nyingi za **processes kuingiliana, kuwasiliana, na kushiriki data**. Ingawa mechanisms hizi ni muhimu kwa uendeshaji wa kawaida wa system, attackers wanaweza kuzitumia vibaya kwa injection, code execution, au data access.

### Library Injection

Library Injection ni technique ambapo attacker **hulazimisha process ipakie library hasidi**. Baada ya ku-inject, library huendeshwa katika context ya target process, na kumpa attacker permissions na access sawa na za process hiyo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking inahusisha **ku-intercept function calls** au messages ndani ya software code. Kwa ku-hook functions, attacker anaweza **kubadilisha tabia** ya process, kuchunguza data nyeti, au hata kupata control ya execution flow.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) inarejelea methods tofauti ambazo processes zilizotengana **hutumia kushiriki na kubadilishana data**. Ingawa IPC ni msingi wa applications nyingi halali, inaweza pia kutumiwa vibaya kuvuruga process isolation, ku-leak taarifa nyeti, au kutekeleza actions zisizoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications zinazo-execute zikiwa na env variables maalum zinaweza kuwa vulnerable kwa process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kufanya **man in the browser attack**, inayowezesha kuiba keystrokes, traffic, cookies, ku-inject scripts kwenye pages...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **hufafanua user interface (UI) elements** na interactions zake ndani ya application. Hata hivyo, zinaweza **kutekeleza arbitrary commands** na **Gatekeeper haizuii** application ambayo tayari ime-execute ku-execute tena ikiwa **NIB file imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya arbitrary programs zitekeleze arbitrary commands:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana ku-inject JVM options kupitia **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, au **`JDK_JAVA_OPTIONS`** na kupakia Java au native agent kabla ya application kuanza.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** hu-preload attacker JavaScript kupitia `--require` (file) au `--import data:text/javascript,…` (fileless, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** hupakia module kwenye interactive REPL, na **`ELECTRON_RUN_AS_NODE`** huwezesha tena yote haya kwenye Electron binaries.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana ku-inject code kwenye .NET applications kupitia **`DOTNET_STARTUP_HOOKS`** kabla ya `Main`, au kwa kutumia vibaya functionality ya .NET debugging wakati prerequisites zake zinapatikana.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash isiyo-interactive husoma **`BASH_ENV`**; POSIX shells za interactive husoma **`ENV`**; zsh husoma **`$ZDOTDIR/.zshenv`**; na fish husoma configuration iliyo chini ya **`XDG_CONFIG_HOME`** au **`XDG_DATA_DIRS`**. Kila moja inaweza ku-execute startup file inayodhibitiwa kabla ya command iliyokusudiwa. Bash pia huendesha command substitution iliyowekwa kwenye **`PS4`** kila xtrace inapowezeshwa (kwa mfano, **`SHELLOPTS=xtrace`** iliyorithiwa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** au **`PHP_INI_SCAN_DIR`** inaweza kupakia PHP configuration inayodhibitiwa, ambayo **`auto_prepend_file`** yake hu-execute kabla ya target script.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Lua interpreter ya standalone hu-execute code au `@file` kutoka **`LUA_INIT`** (au variant yake maalum kwa version) kabla ya kuchakata target script.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** na **`R_PROFILE`** huelekeza startup profiles zilizo na R code. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** pamoja na R library path zinaweza badala yake ku-auto-load package iliyosakinishwa.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** huelekeza depot ambayo `config/startup.jl` yake hu-execute automatically.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`**, au **`ERL_ZFLAGS`** zinaweza ku-inject Erlang VM **`-eval`** expression bila kuhitaji payload file; Elixir workloads kwa kawaida huanzisha VM hiyo hiyo.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** na **`OCTAVE_VERSION_INITFILE`** huelekeza upya startup scripts za Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` ni cross-platform .NET app, kwa hiyo environment variables kadhaa huwezesha execution kabla ya command: **`XDG_CONFIG_HOME`** huelekeza profile scripts zinazoendeshwa wakati wa startup, **`PSModulePath`** hufanya module auto-loading hijack (planted `.psm1` hu-run wakati wa import na inaweza kufunika built-in cmdlets), na variables za .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** pamoja na **`DOTNET_STARTUP_HOOKS`** hupakia attacker code kwenye process kabla ya `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Angalia options tofauti za kufanya Perl script i-execute arbitrary code katika:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Pia inawezekana kutumia vibaya ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) ili kufanya arbitrary scripts zi-execute arbitrary code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** na **`BROWSER`** standard-library chain zinaweza ku-execute command wakati wa warning-filter parsing. Alternative inayotumia file huweka `sitecustomize.py` kwenye **`PYTHONPATH`**, ili initialization ya kawaida ya `site` i-import file hiyo kabla ya target script. **`PYTHONBREAKPOINT`** huendesha callable/module iliyochaguliwa code inapofikia `breakpoint()`. Variables zinazotumika interactive pekee kama **`PYTHONSTARTUP`** zina applicability finyu zaidi.

Kumbuka kwamba executables zilizocompile kwa **`pyinstaller`** hazitatumia environmental variables hizi hata kama zinaendeshwa kwa kutumia embedded python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (na fallback yake ya `EXINIT`) hu-execute kama Ex commands wakati wa startup ya kawaida, kwa hiyo `:!cmd` / `:call system(...)` hutoa code execution victim anapofungua Vim/Neovim ikiwa na controlled environment:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Kando na hilo, Homebrew kwa kawaida husakinisha Python chini ya `/opt/homebrew`, ambapo members wa local `admin` group wanaweza kuwa na uwezo wa kubadilisha launcher. Hii ni writable-binary hijack badala ya environment-variable injection; thibitisha ownership na ACLs kabla ya kuichukulia kuwa exploitable.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni application ya open-source inayotegemea **EndpointSecurity**, ambayo hugundua na kuzuia process injection. Ni reference nzuri ya signals zinazoweza kuonekana kupitia Endpoint Security, kwa kuwa hu-alert kwenye:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** wakati wa process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- Calls za **`task_for_pid`** — process moja ikiomba task port ya nyingine, ambayo ni prerequisite ya ku-inject ndani yake.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, ambazo huanzisha Electron app katika debug mode na kumruhusu mtu yeyote ku-attach na ku-run code ndani yake.<sup>[[3]](#references)</sup>
- **Uundaji wa symlink/hardlink katika privilege levels tofauti** — primitive ya kawaida ya "weka link kama normal user, kisha ielekeze kwenye privileged location". Kumbuka kwamba **symlinks zinaweza ku-alertiwa lakini haziwezi kuzuiwa**: EndpointSecurity haionyeshi link destination kabla ya creation.

### Calls made by other processes

Katika [**blog post hii**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata jinsi inavyowezekana kutumia function **`task_name_for_pid`** kupata taarifa kuhusu **processes zinazo-inject code kwenye process** nyingine na kisha kupata taarifa kuhusu hiyo process nyingine.<sup>[[4]](#references)</sup>

Kumbuka kwamba ili kuita function hiyo unahitaji kuwa na **uid sawa** na ile inayoendesha process au kuwa **root** (na inarudisha taarifa kuhusu process, si njia ya ku-inject code).

## References

- [1] [Shield — detection ya open-source ya macOS process-injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Kwa nini Electron apps haziwezi kuhifadhi secrets zako kwa usiri: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Kugundua task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
