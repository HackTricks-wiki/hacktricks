# Matumizi Mabaya ya Process za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi kuhusu Process

Process ni mfano wa executable inayoendeshwa, hata hivyo process hazitekelezi code; threads ndizo zinazofanya hivyo. Kwa hiyo, **process ni kontena tu za threads zinazoendeshwa** zinazotoa memory, descriptors, ports, permissions...

Kijadi, process zilianzishwa ndani ya process nyingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala halisi ya process ya sasa; kisha **child process** kwa kawaida ingeita **`execve`** ili kupakia executable mpya na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kuharakisha mchakato huu bila kunakili memory.\
Kisha **`posix_spawn`** ilianzishwa, ikiunganisha **`vfork`** na **`execve`** katika mwito mmoja na kukubali flags:

- `POSIX_SPAWN_RESETIDS`: Weka upya effective ids ziwe real ids
- `POSIX_SPAWN_SETPGROUP`: Weka uhusiano wa process group
- `POSUX_SPAWN_SETSIGDEF`: Weka tabia chaguomsingi ya signal
- `POSIX_SPAWN_SETSIGMASK`: Weka signal mask
- `POSIX_SPAWN_SETEXEC`: Tekeleza katika process hiyo hiyo (kama `execve` yenye options zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anzisha ikiwa imesimamishwa
- `_POSIX_SPAWN_DISABLE_ASLR`: Anzisha bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga file descriptions zote kwa chaguomsingi wakati wa exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Fanya high bits za ASLR slide ziwe za nasibu

Zaidi ya hayo, `posix_spawn` hukubali mipangilio ya **`posix_spawnattr`** inayodhibiti vipengele vya process inayoanzishwa, na maingizo ya **`posix_spawn_file_actions`** yanayorekebisha file descriptors.

Process inapokufa hutuma **return code kwa parent process** (ikiwa parent imekufa, parent mpya huwa PID 1) pamoja na signal `SIGCHLD`. Parent inahitaji kupata thamani hii kwa kuita `wait4()` au `waitid()`; hadi hilo litokee, child hubaki katika hali ya zombie, ambapo bado imeorodheshwa lakini haitumii resources.

### PIDs

PIDs, vitambulisho vya process, hutambua process ya kipekee. Katika XNU, **PIDs** zina **bits 64**, huongezeka mfululizo na **hazizunguki kamwe** (ili kuzuia matumizi mabaya).

### Vikundi vya Process, Sessions na Coalations

**Process** zinaweza kuwekwa katika **vikundi** ili kurahisisha kuzidhibiti. Kwa mfano, commands katika shell script zitakuwa katika process group moja, hivyo inawezekana **kuzitumia signal pamoja** kwa kutumia kill, kwa mfano.\
Pia inawezekana **kupanga process katika sessions**. Process inapoanzisha session (`setsid(2)`), child processes huwekwa ndani ya session hiyo, isipokuwa zianzishe session zao wenyewe.

Coalation ni njia nyingine ya kupanga process katika Darwin. Process inapojiunga na coalation, inaweza kufikia rasilimali za pool, kushiriki ledger au kukabiliwa na Jetsam. Coalations zina roles tofauti: Leader, XPC service, Extension.

### Credentials na Personae

Kila process huwa na **credentials** zinazo **bainisha privileges zake** katika mfumo. Kila process huwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa inaweza kuwa mwanachama wa groups kadhaa).\
Pia inawezekana kubadilisha user na group id ikiwa binary ina bit ya `setuid/setgid`.\
Kuna functions kadhaa za **kuweka uids/gids mpya**.

Syscall **`persona`** hutoa seti **mbadala** ya **credentials**. Kukubali persona huweka uid, gid na uanachama wa groups zake **kwa wakati mmoja**. Katika [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:

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

1. **POSIX Threads (pthreads):** macOS inasaidia POSIX threads (`pthreads`), ambazo ni sehemu ya API ya kawaida ya threading kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana katika `/usr/lib/system/libsystem_pthread.dylib`, inayotokana na mradi wa `libpthread` unaopatikana hadharani. Maktaba hii hutoa vitendaji vinavyohitajika kuunda na kudhibiti threads.
2. **Kuunda Threads:** Kitendaji cha `pthread_create()` hutumika kuunda threads mpya. Ndani yake, kitendaji hiki huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini inayohusiana na kernel ya XNU (kernel ambayo macOS imejengwa juu yake). System call hii hupokea flags mbalimbali zinazotokana na `pthread_attr` (sifa), zinazobainisha tabia ya thread, ikiwemo sera za scheduling na ukubwa wa stack.
   - **Ukubwa Chaguo-msingi wa Stack:** Ukubwa chaguo-msingi wa stack kwa threads mpya ni KB 512, ambao unatosha kwa shughuli za kawaida lakini unaweza kurekebishwa kupitia sifa za thread ikiwa nafasi zaidi au kidogo inahitajika.
3. **Uanzishaji wa Thread:** Kitendaji cha `__pthread_init()` ni muhimu wakati wa kusanidi thread, na hutumia hoja ya `env[]` kuchanganua vigeu vya mazingira vinavyoweza kujumuisha maelezo kuhusu eneo na ukubwa wa stack.

#### Kusitishwa kwa Thread katika macOS

1. **Kutoka kwenye Threads:** Kwa kawaida, threads husitishwa kwa kuita `pthread_exit()`. Kitendaji hiki huruhusu thread kutoka kwa usafi, kufanya usafishaji unaohitajika na kuruhusu thread kutuma thamani ya kurudisha kwa threads zozote zinazoiunganisha.
2. **Usafishaji wa Thread:** Baada ya kuita `pthread_exit()`, kitendaji cha `pthread_terminate()` huitwa na kushughulikia uondoaji wa miundo yote ya thread inayohusishwa nayo. Hutoa Mach thread ports (Mach ni mfumo mdogo wa mawasiliano katika kernel ya XNU) na kuita `bsdthread_terminate`, syscall inayoondoa miundo ya kiwango cha kernel inayohusishwa na thread.

#### Mbinu za Usawazishaji

Ili kudhibiti ufikiaji wa rasilimali zinazoshirikiwa na kuepuka hali za race, macOS hutoa primitives kadhaa za usawazishaji. Hizi ni muhimu katika mazingira ya multi-threading ili kuhakikisha uadilifu wa data na uthabiti wa mfumo:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** Mutex ya kawaida yenye ukubwa wa kumbukumbu wa baiti 60 (baiti 56 za mutex na baiti 4 za signature).
   - **Fast Mutex (Signature: 0x4d55545A):** Inafanana na mutex ya kawaida lakini imeboreshwa kwa shughuli za haraka zaidi, pia ina ukubwa wa baiti 60.
2. **Condition Variables:**
   - Hutumika kusubiri hali fulani zitokee, na ina ukubwa wa baiti 44 (baiti 40 pamoja na signature ya baiti 4).
   - **Condition Variable Attributes (Signature: 0x434e4441):** Sifa za usanidi wa condition variables, zenye ukubwa wa baiti 12.
3. **Once Variable (Signature: 0x4f4e4345):**
   - Huhakikisha kuwa kipande cha msimbo wa uanzishaji kitatekelezwa mara moja tu. Kina ukubwa wa baiti 12.
4. **Read-Write Locks:**
   - Huruhusu wasomaji wengi au mwandishi mmoja kwa wakati mmoja, na hivyo kuwezesha ufikiaji bora wa data inayoshirikiwa.
   - **Read Write Lock (Signature: 0x52574c4b):** Ina ukubwa wa baiti 196.
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Sifa za read-write locks, zenye ukubwa wa baiti 20.

> [!TIP]
> Baiti 4 za mwisho za vitu hivyo hutumika kugundua overflow.

### Vigeu vya Ndani vya Thread (TLV)

**Thread Local Variables (TLV)** katika muktadha wa faili za Mach-O (muundo wa executable katika macOS) hutumika kutangaza vigeu mahususi kwa **kila thread** katika programu ya multi-threaded. Hii huhakikisha kuwa kila thread ina nakala yake tofauti ya kigeu, na hivyo kutoa njia ya kuepuka migongano na kudumisha uadilifu wa data bila kuhitaji mbinu za wazi za usawazishaji kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza kigeu cha thread-local kwa kutumia neno kuu **`__thread`**. Hivi ndivyo linavyofanya kazi katika mfano wako:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Kipande hiki kinafafanua `tlv_var` kama kigezo cha ndani ya thread. Kila thread inayoendesha msimbo huu itakuwa na `tlv_var` yake, na mabadiliko ambayo thread moja itafanya kwenye `tlv_var` hayataathiri `tlv_var` katika thread nyingine.

Katika binary ya Mach-O, data inayohusiana na vigezo vya ndani ya thread hupangwa katika sehemu maalum:

- **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu vigezo vya ndani ya thread, kama aina zake na hali ya uanzishaji.
- **`__DATA.__thread_bss`**: Sehemu hii hutumika kwa vigezo vya ndani ya thread ambavyo havijawekewa thamani ya awali waziwazi. Ni sehemu ya kumbukumbu iliyotengwa kwa data inayoanzishwa kwa sifuri.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ya kusimamia vigezo vya ndani ya thread thread inapoisha. API hii hukuwezesha **kusajili destructors**—vitendaji maalum vinavyosafisha data ya ndani ya thread thread inapokoma.

### Vipaumbele vya Thread

Kuelewa vipaumbele vya thread kunahusisha kuchunguza jinsi mfumo wa uendeshaji unavyoamua ni thread zipi zitaendeshwa na lini. Uamuzi huu huathiriwa na kiwango cha kipaumbele kilichowekwa kwa kila thread. Katika macOS na mifumo inayofanana na Unix, hili hushughulikiwa kwa kutumia dhana kama `nice`, `renice`, na madarasa ya Quality of Service (QoS).

#### Nice na Renice

1. **Nice:**
   - Thamani ya `nice` ya process ni nambari inayoathiri kipaumbele chake. Kila process ina thamani ya nice kuanzia -20 (kipaumbele cha juu zaidi) hadi 19 (kipaumbele cha chini zaidi). Thamani chaguomsingi ya nice process inapoundwa kwa kawaida ni 0.
   - Thamani ndogo ya nice (iliyo karibu zaidi na -20) hufanya process iwe na "ubinafsi" zaidi, na kuipa muda zaidi wa CPU ikilinganishwa na process nyingine zilizo na thamani kubwa zaidi za nice.
2. **Renice:**
   - `renice` ni amri inayotumika kubadilisha thamani ya nice ya process ambayo tayari inaendeshwa. Inaweza kutumika kurekebisha kipaumbele cha process kwa nguvu, ama kuongeza au kupunguza mgao wake wa muda wa CPU kulingana na thamani mpya za nice.
   - Kwa mfano, ikiwa process inahitaji rasilimali zaidi za CPU kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Madarasa ya Quality of Service (QoS)

Madarasa ya QoS ni njia ya kisasa zaidi ya kushughulikia vipaumbele vya thread, hasa katika mifumo kama macOS inayotumia **Grand Central Dispatch (GCD)**. Madarasa ya QoS huwawezesha wasanidi programu **kuainisha** kazi katika viwango tofauti kulingana na umuhimu au uharaka wake. macOS husimamia uwekaji wa vipaumbele vya thread kiotomatiki kulingana na madarasa haya ya QoS:

1. **User Interactive:**
   - Darasa hili ni la kazi zinazoingiliana na mtumiaji kwa sasa au zinazohitaji matokeo ya haraka ili kutoa uzoefu mzuri kwa mtumiaji. Kazi hizi hupewa kipaumbele cha juu zaidi ili kiolesura kiendelee kuitikia (kwa mfano, uhuishaji au kushughulikia matukio).
2. **User Initiated:**
   - Kazi ambazo mtumiaji huanzisha na kutarajia matokeo ya haraka, kama kufungua hati au kubofya kitufe kinachohitaji hesabu. Hizi zina kipaumbele cha juu, lakini chini ya User Interactive.
3. **Utility:**
   - Kazi hizi huchukua muda mrefu na kwa kawaida huonyesha kiashiria cha maendeleo (kwa mfano, kupakua faili au kuleta data). Zina kipaumbele cha chini kuliko kazi zilizoanzishwa na mtumiaji na si lazima zikamilike mara moja.
4. **Background:**
   - Darasa hili ni la kazi zinazoendeshwa chinichini na hazionekani kwa mtumiaji. Hizi zinaweza kuwa kazi kama kuorodhesha, kusawazisha au kutengeneza nakala rudufu. Zina kipaumbele cha chini zaidi na athari ndogo sana kwa utendaji wa mfumo.

Kwa kutumia madarasa ya QoS, wasanidi programu hawahitaji kusimamia nambari hususa za kipaumbele; badala yake, huzingatia aina ya kazi, na mfumo huboresha matumizi ya rasilimali za CPU ipasavyo.

Zaidi ya hayo, kuna **sera tofauti za upangaji wa thread** zinazotumika kubainisha seti ya vigezo vya upangaji ambavyo scheduler itazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hii inaweza kuwa muhimu katika mashambulizi ya race condition.

## Matumizi Mabaya ya Process za macOS

macOS hutoa mifumo mingi inayowezesha **process kuingiliana, kuwasiliana na kushiriki data**. Ingawa mifumo hii ni muhimu kwa uendeshaji wa kawaida wa mfumo, washambuliaji wanaweza kuitumia vibaya kwa injection, utekelezaji wa msimbo au ufikiaji wa data.

### Library Injection

Library Injection ni mbinu ambapo mshambuliaji **hulazimisha process kupakia library hasidi**. Baada ya kuingizwa, library huendeshwa katika muktadha wa process lengwa, na kumpa mshambuliaji ruhusa na ufikiaji sawa na wa process hiyo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking huhusisha **kunasa miito ya function** au ujumbe ndani ya msimbo wa programu. Kwa kuweka hooks kwenye functions, mshambuliaji anaweza **kubadilisha tabia** ya process, kuchunguza data nyeti au hata kudhibiti mtiririko wa utekelezaji.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ukurasa huu unaeleza metadata ya ARM64 unwind, vikwazo vya ARM64e PAC na minyororo bandia ya miito.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Mawasiliano kati ya Process

Inter Process Communication (IPC) hurejelea mbinu mbalimbali ambazo process tofauti **hutumia kushiriki na kubadilishana data**. Ingawa IPC ni muhimu kwa programu nyingi halali, pia inaweza kutumiwa vibaya ili kuvunja utenganisho wa process, kuvuja kwa taarifa nyeti au kutekeleza vitendo visivyoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Programu za Electron zinazoendeshwa zikiwa na env variables maalum zinaweza kuwa katika hatari ya process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kutekeleza **shambulio la man in the browser**, linalowezesha kuiba mibofyo ya vitufe, trafiki na cookies, kuingiza scripts kwenye kurasa...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Faili za NIB **hufafanua vipengele vya kiolesura cha mtumiaji (UI)** na mwingiliano wake ndani ya programu. Hata hivyo, zinaweza **kutekeleza amri zozote**, na **Gatekeeper haizuii** programu ambayo tayari imetekelezwa kuendeshwa tena ikiwa **faili ya NIB imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya programu zozote zitekeleze amri zozote:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana kuingiza JVM options kupitia **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** au **`JDK_JAVA_OPTIONS`**, na kupakia Java au native agent kabla programu haijaanza.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** hupakia mapema JavaScript ya mshambuliaji kupitia `--require` (faili) au `--import data:text/javascript,…` (bila faili, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** hupakia module kwenye REPL ya mwingiliano, na **`ELECTRON_RUN_AS_NODE`** huwasha tena yote haya kwenye binary za Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana kuingiza msimbo kwenye programu za .NET kupitia **`DOTNET_STARTUP_HOOKS`** kabla ya `Main`, au kutumia vibaya utendaji wa debugging wa .NET wakati masharti yake ya awali yametimizwa.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash isiyoingiliana husoma **`BASH_ENV`**; POSIX shells zinazoingiliana husoma **`ENV`**; zsh husoma **`$ZDOTDIR/.zshenv`**; na fish husoma usanidi ulio chini ya **`XDG_CONFIG_HOME`** au **`XDG_DATA_DIRS`**. Kila moja inaweza kutekeleza faili ya uanzishaji inayodhibitiwa kabla ya amri iliyokusudiwa. Bash pia huendesha command substitution iliyowekwa kwenye **`PS4`** kila xtrace inapowashwa (kwa mfano, kupitia **`SHELLOPTS=xtrace`** iliyorithiwa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Kuanzisha `/bin/zsh -s` hufanya shell isome programu kutoka kwa standard input. Kwa hiyo, downloader inayonakili hati yenye muundo isiyoaminika hadi kwenye stdin ya child bila kuichanganua kwanza hugeuza hati yote kuwa source ya shell. Loader moja iliyozingatiwa ilisoma faili ya iCalendar ya umma kupitia anonymous pipe, mstari kwa mstari. Metadata ya kalenda ilishindwa kutekelezwa kama amri, lakini zsh iliendelea hadi ilipofikia mistari inayoweza kutekelezeka iliyowekwa baada ya `DESCRIPTION:`. Mistari hiyo ilipakua na kuanzisha application bundle iliyofuata. Content type iliyotarajiwa ya faili na hosting inayoaminika havikuifanya salama; mpaka hatari ulikuwa kupitisha bytes zake kwa interpreter.<sup>[[5]](#references)</sup>

Hatua zinazohusiana zimeelezwa katika [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), na [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** au **`PHP_INI_SCAN_DIR`** zinaweza kupakia usanidi wa PHP unaodhibitiwa ambao **`auto_prepend_file`** yake hutekelezwa kabla ya script lengwa.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Lua interpreter inayojitegemea hutekeleza msimbo au `@file` kutoka **`LUA_INIT`** (au toleo lake maalum) kabla ya kuchakata script lengwa.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** na **`R_PROFILE`** huelekeza kwenye startup profiles zenye msimbo wa R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** pamoja na njia ya R library zinaweza kutumika kupakia kiotomatiki package iliyosakinishwa.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** huelekeza kwenye depot ambayo `config/startup.jl` yake hutekelezwa kiotomatiki.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** au **`ERL_ZFLAGS`** zinaweza kuingiza expression ya Erlang VM **`-eval`** bila kuhitaji faili ya payload; workloads za Elixir kwa kawaida huanzisha VM hiyo hiyo.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** na **`OCTAVE_VERSION_INITFILE`** huelekeza upya startup scripts za Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` ni programu ya .NET inayotumika kwenye mifumo mbalimbali, kwa hiyo environment variables kadhaa huwezesha utekelezaji kabla ya amri: **`XDG_CONFIG_HOME`** huelekeza upya profile scripts zinazoendeshwa wakati wa startup, **`PSModulePath`** huteka nyara upakiaji wa moduli kiotomatiki (faili ya `.psm1` iliyowekwa hapo hutekelezwa wakati wa import na inaweza kuchukua nafasi ya cmdlets zilizojengewa ndani), na variables za .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** na **`DOTNET_STARTUP_HOOKS`** hupakia msimbo wa mshambuliaji kwenye process kabla ya `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Angalia chaguo tofauti za kufanya Perl script itekeleze msimbo wowote katika:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Pia inawezekana kutumia vibaya ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) ili kufanya scripts zozote zitekeleze msimbo wowote:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Mlolongo wa **`PYTHONWARNINGS`** na **`BROWSER`** wa standard library unaweza kutekeleza amri wakati wa kuchanganua warning filter. Njia mbadala inayotumia faili huweka `sitecustomize.py` kwenye **`PYTHONPATH`**, ili uanzishaji wa kawaida wa `site` ui-import kabla ya script lengwa. **`PYTHONBREAKPOINT`** huendesha callable/module iliyochaguliwa msimbo unapofikia `breakpoint()`. Variables zinazotumika tu katika hali ya mwingiliano, kama **`PYTHONSTARTUP`**, zina matumizi finyu zaidi.

Kumbuka kuwa executable zilizokusanywa kwa **`pyinstaller`** hazitatumia environment variables hizi, hata kama zinaendeshwa kwa kutumia embedded Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (na mbadala wake wa `EXINIT`) hutekelezwa kama Ex commands wakati wa startup ya kawaida, kwa hiyo `:!cmd` / `:call system(...)` huwezesha utekelezaji wa msimbo mwathiriwa anapofungua Vim/Neovim akiwa na mazingira yanayodhibitiwa:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Kando na hilo, Homebrew kwa kawaida husakinisha Python chini ya `/opt/homebrew`, ambako wanachama wa kundi la ndani la `admin` wanaweza kuwa na uwezo wa kubadilisha launcher. Huu ni utekaji nyara wa binary inayoweza kuandikwa, si injection kupitia environment variable; hakiki umiliki na ACL kabla ya kuhitimisha kuwa unaweza kutumiwa vibaya.


## Utambuzi

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni programu huria inayotegemea **EndpointSecurity**, inayotambua na kuzuia process injection. Ni rejeleo zuri la kuelewa ishara zinazoweza kuonekana kupitia Endpoint Security, kwani hutoa arifa kuhusu:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** wakati wa process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- Miito ya **`task_for_pid`** — process moja ikiomba task port ya nyingine, ambalo ndilo sharti la awali la kuiingizia msimbo.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, ambazo huanzisha programu ya Electron katika hali ya debug na kuruhusu mtu yeyote kuunganisha na kutekeleza msimbo ndani yake.<sup>[[3]](#references)</sup>
- **Uundaji wa symlink/hardlink katika viwango tofauti vya ruhusa** — mbinu ya kawaida ya "weka link ukiwa mtumiaji wa kawaida, kisha ielekeze kwenye eneo lenye upendeleo". Kumbuka kuwa **symlink zinaweza kuibua arifa lakini haziwezi kuzuiwa**: EndpointSecurity haionyeshi lengwa la link kabla ya kuundwa.

### Miito inayofanywa na process nyingine

Katika [**chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kuona jinsi inavyowezekana kutumia function **`task_name_for_pid`** kupata taarifa kuhusu **process zinazoingiza msimbo kwenye process nyingine**, kisha kupata taarifa kuhusu process hiyo nyingine.<sup>[[4]](#references)</sup>

Kumbuka kuwa ili kuita function hiyo, lazima uwe na **uid sawa** na ile inayoendesha process au uwe **root** (na hurejesha taarifa kuhusu process, si njia ya kuingiza msimbo).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — utambuzi wa process-injection wa macOS wa chanzo huria (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework ya EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Kwa nini programu za Electron haziwezi kuhifadhi siri zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Kutambua mabadiliko ya task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Toleo jipya la MacSync macOS stealer linalenga wapenda crypto na wasanidi programu](https://securelist.com/macsync-new-version/121383/)
