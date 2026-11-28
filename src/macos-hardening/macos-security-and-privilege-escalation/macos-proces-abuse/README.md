# Matumizi Mabaya ya Michakato ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi za Michakato

Process ni mfano wa executable inayoendeshwa; hata hivyo, process hazitekelezi code, bali thread ndizo hufanya hivyo. Kwa hiyo **process ni kontena tu za thread zinazoendeshwa** zinazotoa memory, descriptors, ports, permissions...

Kijadi, processes zilianzishwa ndani ya processes nyingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala halisi ya process ya sasa. Kisha **child process** kwa kawaida ingekuita **`execve`** ili kupakia executable mpya na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kuharakisha mchakato huu bila kunakili memory.\
Kisha **`posix_spawn`** ilianzishwa, ikiunganisha **`vfork`** na **`execve`** katika call moja na kukubali flags:

- `POSIX_SPAWN_RESETIDS`: Rudisha effective ids kwenye real ids
- `POSIX_SPAWN_SETPGROUP`: Weka uhusiano wa process group
- `POSUX_SPAWN_SETSIGDEF`: Weka tabia chaguomsingi ya signal
- `POSIX_SPAWN_SETSIGMASK`: Weka signal mask
- `POSIX_SPAWN_SETEXEC`: Tekeleza kwenye process hiyo hiyo (kama `execve` yenye chaguo zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anza ikiwa imesimamishwa
- `_POSIX_SPAWN_DISABLE_ASLR`: Anza bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga file descriptions zote kwenye exec(2) kwa chaguomsingi
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Badilisha bits za juu za ASLR slide bila mpangilio

Zaidi ya hayo, `posix_spawn` hukubali mipangilio ya **`posix_spawnattr`** inayodhibiti vipengele vya process inayozalishwa, pamoja na maingizo ya **`posix_spawn_file_actions`** yanayorekebisha file descriptors.

Process inapokufa, hutuma **return code kwa parent process** (ikiwa parent imekufa, parent mpya huwa PID 1) kupitia signal `SIGCHLD`. Parent huhitaji kupata thamani hii kwa kuita `wait4()` au `waitid()`. Hadi hilo litokee, child hubaki katika hali ya zombie, ambapo bado imeorodheshwa lakini haitumii resources.

### PIDs

PIDs, yaani process identifiers, hutambulisha process ya kipekee. Katika XNU, **PIDs** zina **bits 64**, huongezeka mfululizo na **hazifiki mwisho wala kuanza upya** (ili kuzuia matumizi mabaya).

### Process Groups, Sessions na Coalations

**Processes** zinaweza kuwekwa katika **groups** ili kurahisisha kuzidhibiti. Kwa mfano, commands katika shell script huwa katika process group moja, hivyo inawezekana **kuzitumia signal pamoja**, kwa mfano kwa kutumia kill.\
Pia inawezekana **kuweka processes katika sessions**. Process inapoanzisha session (`setsid(2)`), child processes huwekwa ndani ya session hiyo, isipokuwa zianzishe session zao wenyewe.

Coalition ni njia nyingine ya kupanga processes katika Darwin. Process inapojiunga na coalition, inaweza kufikia rasilimali za pool, kushiriki ledger au kukabiliwa na Jetsam. Coalations zina roles tofauti: Leader, XPC service, Extension.

### Credentials na Personae

Kila process huwa na **credentials** **zinazotambulisha privileges zake** katika mfumo. Kila process huwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa inaweza kuwa mwanachama wa groups kadhaa).\
Pia inawezekana kubadilisha user na group id ikiwa binary ina bit ya `setuid/setgid`.\
Kuna functions kadhaa za **kuweka uids/gids mpya**.

Syscall **`persona`** hutoa seti **mbadala** ya **credentials**. Kukubali persona kunachukua uid, gid na group memberships zake **kwa wakati mmoja**. Katika [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:

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

## Taarifa za Msingi kuhusu Threads

1. **POSIX Threads (pthreads):** macOS inasaidia POSIX threads (`pthreads`), ambazo ni sehemu ya API ya kawaida ya threading kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana kwenye `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatokana na mradi wa `libpthread` unaopatikana hadharani. Maktaba hii hutoa functions zinazohitajika kuunda na kudhibiti threads.
2. **Kuunda Threads:** Function ya `pthread_create()` hutumika kuunda threads mpya. Ndani yake, function hii huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini inayohusu kernel ya XNU (kernel ambayo macOS imejengwa juu yake). System call hii hupokea flags mbalimbali zinazotokana na `pthread_attr` (attributes) zinazobainisha tabia ya thread, zikiwemo sera za scheduling na ukubwa wa stack.
   - **Ukubwa Chaguomsingi wa Stack:** Ukubwa chaguomsingi wa stack kwa threads mpya ni 512 KB, ambao unatosha kwa shughuli za kawaida lakini unaweza kurekebishwa kupitia thread attributes ikiwa nafasi zaidi au ndogo inahitajika.
3. **Uanzishaji wa Thread:** Function ya `__pthread_init()` ni muhimu wakati wa kusanidi thread, na hutumia argument ya `env[]` kuchanganua environment variables zinazoweza kujumuisha maelezo kuhusu mahali stack ilipo na ukubwa wake.

#### Kusitisha Thread katika macOS

1. **Kutoka kwenye Threads:** Kwa kawaida threads husitishwa kwa kuita `pthread_exit()`. Function hii huruhusu thread kutoka kwa usafi, ikifanya usafishaji unaohitajika na kuiwezesha thread kutuma thamani ya kurudi kwa threads zozote zinazojiunga nayo.
2. **Usafishaji wa Thread:** Baada ya kuita `pthread_exit()`, function ya `pthread_terminate()` huitwa ili kuondoa miundo yote inayohusishwa na thread. Hutoa Mach thread ports (Mach ni mfumo mdogo wa mawasiliano katika kernel ya XNU) na kuita `bsdthread_terminate`, syscall inayoondoa miundo ya kiwango cha kernel inayohusishwa na thread.

#### Mbinu za Synchronization

Ili kudhibiti ufikiaji wa rasilimali zinazoshirikiwa na kuepuka race conditions, macOS hutoa primitives kadhaa za synchronization. Hizi ni muhimu katika mazingira ya multi-threading ili kuhakikisha uadilifu wa data na uthabiti wa mfumo:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** Mutex ya kawaida yenye ukubwa wa kumbukumbu wa bytes 60 (bytes 56 za mutex na bytes 4 za signature).
   - **Fast Mutex (Signature: 0x4d55545A):** Inafanana na regular mutex lakini imeboreshwa kwa operations za haraka zaidi, na pia ina ukubwa wa bytes 60.
2. **Condition Variables:**
   - Hutumika kusubiri hali fulani zitokee, na ina ukubwa wa bytes 44 (bytes 40 pamoja na signature ya bytes 4).
   - **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes za condition variables, zenye ukubwa wa bytes 12.
3. **Once Variable (Signature: 0x4f4e4345):**
   - Huhakikisha kuwa kipande cha code ya uanzishaji kinatekelezwa mara moja tu. Ukubwa wake ni bytes 12.
4. **Read-Write Locks:**
   - Huruhusu readers wengi au writer mmoja kwa wakati mmoja, na kuwezesha ufikiaji bora wa data inayoshirikiwa.
   - **Read Write Lock (Signature: 0x52574c4b):** Ina ukubwa wa bytes 196.
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes za read-write locks, zenye ukubwa wa bytes 20.

> [!TIP]
> Bytes 4 za mwisho za objects hizo hutumika kutambua overflows.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** katika muktadha wa faili za Mach-O (muundo wa executables katika macOS) hutumika kutangaza variables zinazohusika na **kila thread** katika application yenye threads nyingi. Hii huhakikisha kuwa kila thread ina instance yake tofauti ya variable, na kutoa njia ya kuepuka migongano na kudumisha uadilifu wa data bila kuhitaji mbinu za wazi za synchronization kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza variable ya thread-local kwa kutumia keyword ya **`__thread`**. Hivi ndivyo inavyofanya kazi katika mfano wako:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Kipande hiki kinafafanua `tlv_var` kama variable ya thread-local. Kila thread inayoendesha msimbo huu itakuwa na `tlv_var` yake, na mabadiliko ambayo thread moja hufanya kwenye `tlv_var` hayataathiri `tlv_var` katika thread nyingine.

Katika binary ya Mach-O, data inayohusiana na variable za thread-local hupangwa katika sehemu maalum:

- **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu variable za thread-local, kama vile aina zake na hali ya uanzishaji.
- **`__DATA.__thread_bss`**: Sehemu hii hutumiwa kwa variable za thread-local ambazo hazijawekewa thamani ya awali waziwazi. Ni sehemu ya kumbukumbu iliyotengwa kwa data inayoanzishwa kwa sifuri.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ya kusimamia variable za thread-local thread inapomaliza. API hii huruhusu **kusajili destructors**—function maalum zinazosafisha data ya thread-local thread inapositishwa.

### Vipaumbele vya Thread

Kuelewa vipaumbele vya thread kunahusisha kuangalia jinsi mfumo wa uendeshaji unavyoamua ni thread zipi zitakazoendeshwa na lini. Uamuzi huu huathiriwa na kiwango cha kipaumbele kilichopewa kila thread. Katika macOS na mifumo inayofanana na Unix, hili hushughulikiwa kwa kutumia dhana kama `nice`, `renice`, na madarasa ya Quality of Service (QoS).

#### Nice na Renice

1. **Nice:**
   - Thamani ya `nice` ya mchakato ni nambari inayoathiri kipaumbele chake. Kila mchakato una thamani ya nice kati ya -20 (kipaumbele cha juu zaidi) na 19 (kipaumbele cha chini zaidi). Thamani ya kawaida ya nice wakati mchakato unapoundwa kwa kawaida ni 0.
   - Thamani ya chini ya nice (inayokaribia -20) hufanya mchakato uwe "mbinafsi" zaidi, na kuupa muda mwingi zaidi wa CPU ikilinganishwa na michakato mingine yenye thamani za nice zilizo juu zaidi.
2. **Renice:**
   - `renice` ni amri inayotumiwa kubadilisha thamani ya nice ya mchakato ambao tayari unaendeshwa. Inaweza kutumiwa kurekebisha kipaumbele cha michakato wakati wa utekelezaji, kwa kuongeza au kupunguza mgao wake wa muda wa CPU kulingana na thamani mpya za nice.
   - Kwa mfano, ikiwa mchakato unahitaji rasilimali zaidi za CPU kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Madarasa ya Quality of Service (QoS)

Madarasa ya QoS ni njia ya kisasa zaidi ya kushughulikia vipaumbele vya thread, hasa katika mifumo kama macOS inayotumia **Grand Central Dispatch (GCD)**. Madarasa ya QoS huruhusu developers **kuainisha** kazi katika viwango tofauti kulingana na umuhimu au uharaka wake. macOS husimamia vipaumbele vya thread kiotomatiki kulingana na madarasa haya ya QoS:

1. **User Interactive:**
   - Darasa hili ni la kazi zinazoingiliana na mtumiaji wakati huo au zinazohitaji matokeo ya haraka ili kutoa matumizi mazuri kwa mtumiaji. Kazi hizi hupewa kipaumbele cha juu zaidi ili kiolesura kiendelee kuitikia (kwa mfano, uhuishaji au ushughulikiaji wa matukio).
2. **User Initiated:**
   - Kazi ambazo mtumiaji ameanzisha na anatarajia matokeo ya haraka, kama kufungua hati au kubofya kitufe kinachohitaji hesabu. Kazi hizi zina kipaumbele cha juu, lakini kiko chini ya User Interactive.
3. **Utility:**
   - Kazi hizi huchukua muda mrefu na kwa kawaida huonyesha kiashiria cha maendeleo (kwa mfano, kupakua faili au kuingiza data). Kipaumbele chake ni cha chini kuliko kazi zilizoanzishwa na mtumiaji, na hazihitaji kukamilika mara moja.
4. **Background:**
   - Darasa hili ni la kazi zinazoendeshwa chinichini na hazionekani kwa mtumiaji. Hizi zinaweza kuwa kazi kama kuorodhesha, kusawazisha au kuhifadhi nakala rudufu. Zina kipaumbele cha chini zaidi na athari ndogo kwa utendaji wa mfumo.

Kwa kutumia madarasa ya QoS, developers hawahitaji kusimamia nambari hususa za vipaumbele, bali huzingatia aina ya kazi; kisha mfumo huboresha rasilimali za CPU ipasavyo.

Zaidi ya hayo, kuna **sera tofauti za upangaji wa thread** zinazobainisha seti ya vigezo vya upangaji ambavyo scheduler itazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Linaweza kuwa na manufaa katika mashambulizi ya race condition.

## Matumizi Mabaya ya Michakato ya macOS

macOS hutoa mbinu nyingi za **michakato kuingiliana, kuwasiliana na kushiriki data**. Ingawa mbinu hizi ni muhimu kwa uendeshaji wa kawaida wa mfumo, washambuliaji wanaweza kuzitumia vibaya kwa injection, utekelezaji wa msimbo au ufikiaji wa data.

### Library Injection

Library Injection ni mbinu ambayo mshambuliaji **hulazimisha mchakato kupakia library hasidi**. Baada ya kuingizwa, library huendeshwa katika muktadha wa mchakato lengwa, na kumpa mshambuliaji ruhusa na ufikiaji sawa na wa mchakato huo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking huhusisha **kunasa miito ya function** au ujumbe ndani ya msimbo wa programu. Kwa ku-hook function, mshambuliaji anaweza **kubadilisha tabia** ya mchakato, kuchunguza data nyeti au hata kudhibiti mtiririko wa utekelezaji.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ukurasa huu unahusu metadata ya ARM64 unwind, vizuizi vya PAC vya arm64e na minyororo ya simu bandia.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) hurejelea mbinu tofauti ambazo michakato tofauti **hutumia kushiriki na kubadilishana data**. Ingawa IPC ni muhimu kwa programu nyingi halali, inaweza pia kutumiwa vibaya kukwepa utenganishaji wa michakato, kuvuja taarifa nyeti au kutekeleza vitendo visivyoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Programu za Electron zinazoendeshwa zikiwa na env variables maalum zinaweza kuwa hatarini kwa process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kutekeleza **shambulizi la man in the browser**, na hivyo kuiba mibofyo ya vitufe, trafiki na cookies, na kuingiza scripts kwenye kurasa...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Faili za NIB **hufafanua vipengele vya user interface (UI)** na mwingiliano wake ndani ya programu. Hata hivyo, zinaweza **kutekeleza amri kiholela**, na **Gatekeeper haizuii** programu ambayo tayari imeendeshwa kuendeshwa tena ikiwa **faili ya NIB imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya programu yoyote kutekeleza amri kiholela:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana kuingiza chaguo za JVM kupitia **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, au **`JDK_JAVA_OPTIONS`** na kupakia Java au native agent kabla programu haijaanza.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** hupakia mapema JavaScript ya mshambuliaji kupitia `--require` (faili) au `--import data:text/javascript,…` (bila faili, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** hupakia module kwenye REPL inayoingiliana, na **`ELECTRON_RUN_AS_NODE`** huwezesha tena haya yote kwenye binary za Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana kuingiza msimbo kwenye programu za .NET kupitia **`DOTNET_STARTUP_HOOKS`** kabla ya `Main`, au kutumia vibaya utendaji wa debugging wa .NET wakati masharti yake ya awali yametimizwa.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash isiyoingiliana husoma **`BASH_ENV`**; shells za POSIX zinazoingiliana husoma **`ENV`**; zsh husoma **`$ZDOTDIR/.zshenv`**; na fish husoma usanidi ulio chini ya **`XDG_CONFIG_HOME`** au **`XDG_DATA_DIRS`**. Kila moja inaweza kutekeleza faili ya startup inayodhibitiwa kabla ya amri iliyokusudiwa. Bash pia huendesha command substitution iliyowekwa kwenye **`PS4`** kila xtrace inapowashwa (kwa mfano, kupitia **`SHELLOPTS=xtrace`** iliyorithiwa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Kuanzisha `/bin/zsh -s` husababisha shell kusoma programu kutoka kwa standard input. Kwa hiyo, downloader inay nakili hati yenye muundo isiyoaminika kwenye stdin ya child bila kuichanganua kwanza, hugeuza hati nzima kuwa chanzo cha shell. Loader moja iliyozingatiwa ilipitisha faili ya iCalendar ya umma kupitia anonymous pipe, mstari kwa mstari. Metadata ya kalenda ilishindwa kama amri, lakini zsh iliendelea hadi ilipofikia mistari inayoweza kutekelezwa iliyowekwa baada ya `DESCRIPTION:`. Mistari hiyo ilipakua na kuwasha application bundle iliyofuata. Aina ya maudhui iliyotarajiwa na uhosting unaoaminika wa carrier havikufanya hili liwe salama; mpaka hatari ulikuwa kupitisha bytes zake kwa interpreter.<sup>[[5]](#references)</sup>

Hatua zinazohusiana zimefafanuliwa katika [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), na [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** au **`PHP_INI_SCAN_DIR`** zinaweza kupakia usanidi wa PHP unaodhibitiwa ambao **`auto_prepend_file`** yake hutekelezwa kabla ya script lengwa.

[Usanidi wa PHP na injection ya startup kupitia `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Lua interpreter inayojitegemea hutekeleza msimbo au `@file` kutoka **`LUA_INIT`** (au toleo lake mahususi) kabla ya kushughulikia script lengwa.

[Injection ya startup ya Lua kupitia `LUA_INIT` (faili na msimbo wa ndani)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** na **`R_PROFILE`** huelekeza kwenye startup profiles zilizo na msimbo wa R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** pamoja na njia ya R library vinaweza badala yake kupakia kiotomatiki package iliyosakinishwa.

[Startup profiles za R na upakiaji wa package](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** huelekeza kwenye depot ambayo `config/startup.jl` yake hutekelezwa kiotomatiki.

[Injection ya Julia kupitia `JULIA_DEPOT_PATH` na `startup.jl`](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`**, au **`ERL_ZFLAGS`** zinaweza kuingiza expression ya Erlang VM **`-eval`** bila kuhitaji faili ya payload; workloads za Elixir kwa kawaida huanzisha VM hiyo hiyo.

[Injection ya flags za Erlang/Elixir VM](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** na **`OCTAVE_VERSION_INITFILE`** huelekeza kwenye startup scripts za Octave.

[Injection ya startup-file ya GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` ni programu ya .NET inayofanya kazi kwenye mifumo mbalimbali, kwa hiyo env variables kadhaa huwezesha utekelezaji kabla ya amri: **`XDG_CONFIG_HOME`** huelekeza kwenye profile scripts zinazoendeshwa wakati wa startup, **`PSModulePath`** huteka nyara upakiaji wa module kiotomatiki (`.psm1` iliyowekwa hutekelezwa wakati wa ku-import na inaweza kufunika cmdlets zilizojengewa ndani), na variables za .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** na **`DOTNET_STARTUP_HOOKS`** hupakia msimbo wa mshambuliaji kwenye mchakato kabla ya `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Angalia chaguo tofauti za kufanya script ya Perl itekeleze msimbo kiholela katika:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Inawezekana pia kutumia vibaya env variables za ruby (**`RUBYOPT`**, **`RUBYLIB`**) ili kufanya scripts kiholela zitekeleze msimbo kiholela:


[Chaguo za loader za Ruby `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Mnyororo wa **`PYTHONWARNINGS`** na **`BROWSER`** wa standard library unaweza kutekeleza amri wakati wa kuchanganua warning filter. Njia mbadala inayotumia faili huweka `sitecustomize.py` kwenye **`PYTHONPATH`** ili uanzishaji wa kawaida wa `site` ui-import kabla ya script lengwa. **`PYTHONBREAKPOINT`** huendesha callable/module iliyochaguliwa msimbo unapofikia `breakpoint()`.

Kwenye CPython 3.13+, **`PYTHONINSPECT`** inaweza pia kuendesha faili ya **`PYTHONSTARTUP`** baada ya script pale PyREPL yake inapoanzishwa kwenye terminal.<sup>[[6]](#references)</sup>

Kumbuka kuwa executable zilizokusanywa kwa **`pyinstaller`** hazitatumia env variables hizi hata zinapoendeshwa kwa kutumia python iliyopachikwa.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (na mbadala wake wa `EXINIT`) hutekelezwa kama amri za Ex wakati wa startup ya kawaida, kwa hiyo `:!cmd` / `:call system(...)` huwezesha utekelezaji wa msimbo mwathiriwa anapofungua Vim/Neovim akiwa na mazingira yanayodhibitiwa:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Kando na hilo, Homebrew kwa kawaida husakinisha Python chini ya `/opt/homebrew`, ambapo wanachama wa kundi la ndani la `admin` wanaweza kuweza kubadilisha launcher. Huku ni kuteka nyara binary inayoweza kuandikwa, si injection kupitia env variable; hakiki umiliki na ACL kabla ya kudhani kuwa kuna uwezekano wa kulitumia vibaya.


## Ugunduzi

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni programu ya chanzo huria inayotegemea **EndpointSecurity** na hugundua na kuzuia process injection. Ni rejea nzuri ya kuelewa ishara zinazoweza kuonekana kupitia Endpoint Security, kwa kuwa hutoa arifa kuhusu:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** wakati wa process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- Miito ya **`task_for_pid`** — mchakato mmoja ukiomba task port ya mwingine, ambayo ni sharti la awali la kuingiza msimbo ndani yake.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, ambazo huanzisha programu ya Electron katika hali ya debug na kumruhusu yeyote kujiunganisha na kutekeleza msimbo ndani yake.<sup>[[3]](#references)</sup>
- **Kuunda symlink/hardlink kati ya viwango vya ruhusa** — mbinu ya kawaida ya "kuweka link kama mtumiaji wa kawaida, kisha kuielekeza kwenye eneo lenye ruhusa za juu". Kumbuka kuwa **symlink zinaweza kuibua arifa lakini haziwezi kuzuiwa**: EndpointSecurity haionyeshi lengwa la link kabla ya kuundwa.

### Miito inayofanywa na michakato mingine

Katika [**chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata maelezo ya jinsi inavyowezekana kutumia function **`task_name_for_pid`** kupata taarifa kuhusu **michakato mingine inayodunga msimbo kwenye mchakato**, kisha kupata taarifa kuhusu mchakato huo mwingine.<sup>[[4]](#references)</sup>

Kumbuka kuwa ili kuita function hiyo, unahitaji kuwa na **uid sawa** na ile inayoendesha mchakato au kuwa **root** (na hurejesha taarifa kuhusu mchakato, si njia ya kuingiza msimbo).



## References

- [1] [Shield — ugunduzi wa process injection wa macOS wa chanzo huria (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — mfumo wa EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Kwa nini programu za Electron haziwezi kuhifadhi siri zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Kugundua marekebisho ya task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Toleo jipya la mwizi wa macOS MacSync linalenga wapenda crypto na developers](https://securelist.com/macsync-new-version/121383/)
- [6] [Mstari wa amri na mazingira ya Python — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
