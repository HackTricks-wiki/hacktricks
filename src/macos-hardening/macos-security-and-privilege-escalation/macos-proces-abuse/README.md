# Matumizi Mabaya ya Process za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi kuhusu Process

Process ni instance ya executable inayotekelezwa, hata hivyo process hazitekelezi code; threads ndizo hufanya hivyo. Kwa hiyo, **process ni containers tu za kuendesha threads** zinazotoa memory, descriptors, ports, permissions...

Kijadi, process zilianzishwa ndani ya process nyingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala halisi ya process ya sasa, kisha **child process** kwa kawaida ingeita **`execve`** ili kupakia executable mpya na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kufanya process hii iwe ya haraka bila kunakili memory.\
Kisha **`posix_spawn`** ilianzishwa kwa kuchanganya **`vfork`** na **`execve`** katika call moja na kukubali flags:

- `POSIX_SPAWN_RESETIDS`: Weka upya effective ids ziwe real ids
- `POSIX_SPAWN_SETPGROUP`: Weka uhusiano wa process group
- `POSUX_SPAWN_SETSIGDEF`: Weka tabia chaguo-msingi ya signal
- `POSIX_SPAWN_SETSIGMASK`: Weka signal mask
- `POSIX_SPAWN_SETEXEC`: Fanya exec katika process hiyo hiyo (kama `execve` yenye options zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anzisha ikiwa suspended
- `_POSIX_SPAWN_DISABLE_ASLR`: Anzisha bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga file descriptions zote kwenye exec(2) kwa default
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomize high bits za ASLR slide

Zaidi ya hayo, `posix_spawn` inakubali settings za **`posix_spawnattr`** zinazodhibiti vipengele vya process iliyoanzishwa, pamoja na entries za **`posix_spawn_file_actions`** zinazorekebisha file descriptors.

Process inapokufa, hutuma **return code kwa parent process** (ikiwa parent ilikufa, parent mpya huwa PID 1) kwa signal `SIGCHLD`. Parent inahitaji kupata value hii kwa kuita `wait4()` au `waitid()`, na hadi hilo litokee child hubaki katika hali ya zombie, ambapo bado imeorodheshwa lakini haitumii resources.

### PIDs

PIDs, au process identifiers, hutambulisha process ya kipekee. Katika XNU, **PIDs** zina **64 bits**, huongezeka kwa mpangilio, na **hazifanyi wrap** (ili kuzuia matumizi mabaya).

### Process Groups, Sessions & Coalitions

**Process** zinaweza kuwekwa katika **groups** ili kurahisisha kuzishughulikia. Kwa mfano, commands katika shell script zitakuwa katika process group moja, hivyo inawezekana **kuzitumia signal pamoja** kwa kutumia kill, kwa mfano.\
Pia inawezekana **kuweka process katika sessions**. Process inapoanzisha session (`setsid(2)`), child processes huwekwa ndani ya session hiyo, isipokuwa zianzishe session zao wenyewe.

Coalition ni njia nyingine ya kupanga process katika Darwin. Process inapojiunga na coalition, inaruhusiwa kufikia pool resources, kushiriki ledger au kukabiliwa na Jetsam. Coalitions zina roles tofauti: Leader, XPC service, Extension.

### Credentials & Personae

Kila process huwa na **credentials** zinazo **tambua privileges zake** katika mfumo. Kila process itakuwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa inaweza kuwa katika groups kadhaa).\
Pia inawezekana kubadilisha user na group id ikiwa binary ina bit ya **`setuid/setgid`**.\
Kuna functions kadhaa za **kuweka uids/gids mpya**.

Syscall **`persona`** hutoa seti **mbadala** ya **credentials**. Kupitisha persona kunachukua uid, gid na group memberships zake **kwa pamoja**. Katika [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:
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
## Taarifa Msingi kuhusu Threads

1. **POSIX Threads (pthreads):** macOS inasaidia POSIX threads (`pthreads`), ambazo ni sehemu ya API ya kawaida ya threading kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana kwenye `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatokana na project ya `libpthread` inayopatikana hadharani. Library hii hutoa functions zinazohitajika kuunda na kudhibiti threads.
2. **Kuunda Threads:** Function ya `pthread_create()` hutumika kuunda threads mpya. Ndani yake, function hii huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini maalum kwa XNU kernel (kernel ambayo macOS inategemea). System call hii hupokea flags mbalimbali zinazotokana na `pthread_attr` (attributes), zinazobainisha tabia ya thread, zikiwemo scheduling policies na ukubwa wa stack.
- **Ukubwa wa Kawaida wa Stack:** Ukubwa wa kawaida wa stack kwa threads mpya ni 512 KB, ambao unatosha kwa operations za kawaida lakini unaweza kurekebishwa kupitia thread attributes ikiwa nafasi zaidi au kidogo inahitajika.
3. **Uanzishaji wa Thread:** Function ya `__pthread_init()` ni muhimu wakati wa kusanidi thread, kwa kutumia argument ya `env[]` kuchanganua environment variables ambazo zinaweza kujumuisha maelezo kuhusu eneo na ukubwa wa stack.

#### Kusitisha Threads katika macOS

1. **Kutoka kwa Threads:** Kwa kawaida threads husitishwa kwa kuita `pthread_exit()`. Function hii huruhusu thread kutoka kwa usafi, ikifanya cleanup inayohitajika na kuruhusu thread kutuma return value kwa joiners wowote.
2. **Cleanup ya Thread:** Baada ya kuita `pthread_exit()`, function ya `pthread_terminate()` huitwa. Function hii hushughulikia kuondoa miundo yote inayohusishwa na thread. Hutoa Mach thread ports (Mach ni mfumo mdogo wa mawasiliano ndani ya XNU kernel) na kuita `bsdthread_terminate`, ambayo ni syscall inayoondoa miundo ya kiwango cha kernel inayohusishwa na thread.

#### Mechanisms za Synchronization

Ili kudhibiti ufikiaji wa shared resources na kuzuia race conditions, macOS hutoa synchronization primitives kadhaa. Hizi ni muhimu katika mazingira ya multi-threading ili kuhakikisha uadilifu wa data na uthabiti wa mfumo:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Mutex ya kawaida yenye memory footprint ya bytes 60 (bytes 56 kwa mutex na bytes 4 kwa signature).
- **Fast Mutex (Signature: 0x4d55545A):** Inafanana na mutex ya kawaida lakini imeboreshwa kwa operations za haraka zaidi, pia ikiwa na ukubwa wa bytes 60.
2. **Condition Variables:**
- Hutumika kusubiri conditions fulani zitokee, zikiwa na ukubwa wa bytes 44 (bytes 40 pamoja na signature ya bytes 4).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes za condition variables, zikiwa na ukubwa wa bytes 12.
3. **Once Variable (Signature: 0x4f4e4345):**
- Huhakikisha kuwa sehemu ya initialization code inatekelezwa mara moja pekee. Ukubwa wake ni bytes 12.
4. **Read-Write Locks:**
- Huruhusu readers wengi au writer mmoja kwa wakati mmoja, na hivyo kuwezesha ufikiaji bora wa shared data.
- **Read Write Lock (Signature: 0x52574c4b):** Ina ukubwa wa bytes 196.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes za read-write locks, zikiwa na ukubwa wa bytes 20.

> [!TIP]
> Bytes 4 za mwisho za objects hizo hutumika kugundua overflows.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** katika muktadha wa Mach-O files (format ya executables katika macOS) hutumika kutangaza variables ambazo ni maalum kwa **kila thread** katika application yenye multi-threading. Hii huhakikisha kuwa kila thread ina instance yake tofauti ya variable, na kutoa njia ya kuzuia conflicts na kudumisha uadilifu wa data bila kuhitaji synchronization mechanisms kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza thread-local variable kwa kutumia keyword ya **`__thread`**. Hivi ndivyo inavyofanya kazi katika mfano wako:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Snippet hii inafafanua `tlv_var` kama thread-local variable. Kila thread inayoendesha code hii itakuwa na `tlv_var` yake, na mabadiliko ambayo thread moja hufanya kwenye `tlv_var` hayataathiri `tlv_var` katika thread nyingine.

Katika binary ya Mach-O, data inayohusiana na thread local variables hupangwa katika sections maalum:

- **`__DATA.__thread_vars`**: Section hii ina metadata kuhusu thread-local variables, kama vile aina zake na hali ya initialization.
- **`__DATA.__thread_bss`**: Section hii hutumika kwa thread-local variables ambazo hazijawekewa initialization wazi. Ni sehemu ya memory iliyotengwa kwa data iliyoanzishwa kwa zero.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ya kusimamia thread-local variables thread inapotoka. API hii inakuruhusu **kusajili destructors**—functions maalum zinazosafisha thread-local data thread inapokoma.

### Threading Priorities

Kuelewa thread priorities kunahusisha kuangalia jinsi operating system inavyoamua ni threads zipi ziendeshe na wakati gani. Uamuzi huu huathiriwa na kiwango cha priority kilichowekwa kwa kila thread. Katika macOS na Unix-like systems, hili hushughulikiwa kwa kutumia dhana kama `nice`, `renice`, na Quality of Service (QoS) classes.

#### Nice and Renice

1. **Nice:**
- Thamani ya `nice` ya process ni namba inayoathiri priority yake. Kila process ina nice value kuanzia -20 (priority ya juu zaidi) hadi 19 (priority ya chini zaidi). Nice value ya kawaida process inapoundwa kwa kawaida ni 0.
- Nice value ya chini (iliyo karibu na -20) hufanya process iwe ya "selfish" zaidi, ikiipa CPU time zaidi ikilinganishwa na processes nyingine zilizo na nice values za juu.
2. **Renice:**
- `renice` ni command inayotumika kubadilisha nice value ya process ambayo tayari inaendesha. Hii inaweza kutumika kurekebisha priority ya processes dynamically, kwa kuongeza au kupunguza mgao wao wa CPU time kulingana na nice values mpya.
- Kwa mfano, ikiwa process inahitaji CPU resources zaidi kwa muda, unaweza kupunguza nice value yake kwa kutumia `renice`.

#### Quality of Service (QoS) Classes

QoS classes ni mbinu ya kisasa zaidi ya kushughulikia thread priorities, hasa katika systems kama macOS zinazotumia **Grand Central Dispatch (GCD)**. QoS classes huwawezesha developers **kuainisha** kazi katika viwango tofauti kulingana na umuhimu au uharaka wake. macOS husimamia thread prioritization automatically kulingana na QoS classes hizi:

1. **User Interactive:**
- Class hii ni ya tasks zinazoingiliana na user kwa sasa au zinazohitaji matokeo ya haraka ili kutoa user experience nzuri. Tasks hizi hupewa priority ya juu zaidi ili interface ibaki responsive (kwa mfano, animations au event handling).
2. **User Initiated:**
- Tasks zinazoanzishwa na user na ambazo user anatarajia zipate matokeo mara moja, kama kufungua document au kubofya button inayohitaji computations. Hizi zina priority ya juu, lakini iko chini ya user interactive.
3. **Utility:**
- Tasks hizi hudumu kwa muda mrefu na kwa kawaida huonyesha progress indicator (kwa mfano, kudownload files au kuimport data). Zina priority ya chini kuliko tasks zilizoanzishwa na user na hazihitaji kukamilika mara moja.
4. **Background:**
- Class hii ni ya tasks zinazoendesha background na hazionekani kwa user. Hizi zinaweza kuwa tasks kama indexing, syncing, au backups. Zina priority ya chini zaidi na athari ndogo kwenye performance ya system.

Kwa kutumia QoS classes, developers hawahitaji kusimamia namba halisi za priority, bali huzingatia aina ya task, na system huboresha matumizi ya CPU resources ipasavyo.

Zaidi ya hayo, kuna **thread scheduling policies** tofauti zinazobainisha seti ya scheduling parameters ambazo scheduler itazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hii inaweza kuwa muhimu katika race condition attacks.

## macOS Process Abuse

macOS hutoa mechanisms nyingi za **processes kuingiliana, kuwasiliana, na kushirikiana data**. Ingawa mechanisms hizi ni muhimu kwa uendeshaji wa kawaida wa system, attackers wanaweza kuzitumia vibaya kwa injection, code execution, au data access.

### Library Injection

Library Injection ni technique ambayo attacker **hulazimisha process ipakie malicious library**. Baada ya kuingizwa, library hiyo huendesha katika context ya target process, na kumpa attacker permissions na access sawa na za process hiyo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking inahusisha **kukatiza function calls** au messages ndani ya software code. Kwa kuhook functions, attacker anaweza **kubadilisha tabia** ya process, kuchunguza sensitive data, au hata kupata control ya execution flow.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) inarejelea methods tofauti ambazo processes zilizotenganishwa hutumia **kushirikiana na kubadilishana data**. Ingawa IPC ni ya msingi kwa applications nyingi halali, inaweza pia kutumiwa vibaya kuvuruga process isolation, kuvuja sensitive information, au kutekeleza actions zisizoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications zinazoendeshwa zikiwa na env variables maalum zinaweza kuwa vulnerable kwa process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kutekeleza **man in the browser attack**, inayoruhusu kuiba keystrokes, traffic, cookies, kuinject scripts kwenye pages...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **hufafanua user interface (UI) elements** na interactions zake ndani ya application. Hata hivyo, zinaweza **kutekeleza arbitrary commands** na **Gatekeeper haizuii** application ambayo tayari imetekelezwa kuendelea kutekelezwa ikiwa **NIB file imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya arbitrary programs zitekeleze arbitrary commands:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana kuinject JVM options kupitia **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, au **`JDK_JAVA_OPTIONS`** na kupakia Java au native agent kabla application haijaanza.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana kuinject code katika .NET applications kupitia **`DOTNET_STARTUP_HOOKS`** kabla ya `Main`, au kwa kutumia vibaya .NET debugging functionality wakati prerequisites zake zipo.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash isiyo-interactive husoma **`BASH_ENV`**; zsh husoma **`$ZDOTDIR/.zshenv`**; na fish husoma configuration iliyo chini ya **`XDG_CONFIG_HOME`** au **`XDG_DATA_DIRS`**. Kila moja inaweza kutekeleza controlled startup file kabla ya command iliyokusudiwa:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** au **`PHP_INI_SCAN_DIR`** inaweza kupakia controlled PHP configuration ambayo **`auto_prepend_file`** yake hutekelezwa kabla ya target script.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Standalone Lua interpreter hutekeleza code au `@file` kutoka **`LUA_INIT`** (au variant yake inayotegemea version) kabla ya kuchakata target script.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** na **`R_PROFILE`** huelekeza upya startup profiles zenye R code. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** pamoja na R library path vinaweza badala yake kuauto-load package iliyosakinishwa.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** huelekeza upya depot ambayo `config/startup.jl` yake hutekelezwa automatically.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`**, au **`ERL_ZFLAGS`** zinaweza kuinject Erlang VM **`-eval`** expression bila kuhitaji payload file; Elixir workloads kwa kawaida huanzisha VM hiyo hiyo.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** na **`OCTAVE_VERSION_INITFILE`** huelekeza upya Octave startup scripts.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

Katika macOS na Linux, **`XDG_CONFIG_HOME`** inaweza kuelekeza upya PowerShell user profiles zinazotekelezwa `pwsh` inapoanza.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Angalia options tofauti za kufanya Perl script itekeleze arbitrary code katika:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Pia inawezekana kutumia vibaya ruby env variables ili kufanya arbitrary scripts zitekeleze arbitrary code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** na **`BROWSER`** standard-library chain zinaweza kutekeleza command wakati wa warning-filter parsing. Njia mbadala inayotumia file huweka `sitecustomize.py` kwenye **`PYTHONPATH`**, ili `site` initialization ya kawaida iimport file hiyo kabla ya target script. Variables zinazotumika kwa interactive pekee, kama **`PYTHONSTARTUP`**, zina applicability finyu zaidi.

Kumbuka kwamba executables zilizocompile kwa kutumia **`pyinstaller`** hazitatumia environmental variables hizi hata kama zinaendesha kwa kutumia embedded python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

Tofauti na hayo, Homebrew kwa kawaida husakinisha Python chini ya `/opt/homebrew`, ambapo members wa local `admin` group wanaweza kuwa na uwezo wa kubadilisha launcher. Hii ni writable-binary hijack badala ya environment-variable injection; thibitisha ownership na ACLs kabla ya kuichukulia kama exploitable.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni open-source **EndpointSecurity**-based application inayogundua na kuzuia process injection. Ni reference nzuri ya signals zinazoweza kuonekana kupitia Endpoint Security, kwa kuwa hutoa alerts kuhusu:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** wakati wa process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** calls — process moja ikiomba task port ya nyingine, ambayo ni prerequisite ya kuinject ndani yake.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, zinazoanzisha Electron app katika debug mode na kumruhusu yeyote kuattach na kuendesha code ndani yake.<sup>[[3]](#references)</sup>
- **Uundaji wa symlink/hardlink katika privilege levels tofauti** — primitive ya kawaida ya "kuweka link kama normal user, kisha kuielekeza kwenye privileged location". Kumbuka kwamba **symlinks zinaweza kuwekewa alert lakini haziwezi kuzuiwa**: EndpointSecurity haionyeshi link destination kabla ya creation.

### Calls made by other processes

Katika [**blog post hii**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata jinsi ya kutumia function **`task_name_for_pid`** kupata taarifa kuhusu **processes zinazoinject code katika process** na kisha kupata taarifa kuhusu hiyo process nyingine.<sup>[[4]](#references)</sup>

Kumbuka kwamba ili kuita function hiyo unahitaji kuwa na **uid** sawa na ile inayotumia process, au uwe **root** (na inarejesha taarifa kuhusu process, si njia ya kuinject code).

## References

- [1] [Shield — open-source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Kwa nini Electron apps haziwezi kuhifadhi secrets zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Kugundua task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
