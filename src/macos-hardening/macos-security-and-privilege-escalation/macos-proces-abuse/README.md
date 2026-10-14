# Matumizi Mabaya ya Michakato ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi kuhusu Michakato

Mchakato ni mfano wa programu inayotekelezwa, hata hivyo michakato haiendeshi msimbo; nyuzi ndizo zinazofanya hivyo. Kwa hiyo **michakato ni vyombo tu vya kuendeshea nyuzi** vinavyotoa kumbukumbu, vifafanuzi, milango, ruhusa...

Kwa kawaida, michakato ilianzishwa ndani ya michakato mingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala kamili ya mchakato wa sasa, kisha **mchakato mtoto** kwa kawaida ungeita **`execve`** kupakia programu mpya na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kuharakisha mchakato huu bila kunakili kumbukumbu.\
Kisha **`posix_spawn`** ilianzishwa, ikiunganisha **`vfork`** na **`execve`** katika mwito mmoja na kukubali bendera hizi:

- `POSIX_SPAWN_RESETIDS`: Rudisha vitambulisho vinavyotumika kwenye vitambulisho halisi
- `POSIX_SPAWN_SETPGROUP`: Weka uhusiano wa kikundi cha michakato
- `POSUX_SPAWN_SETSIGDEF`: Weka tabia chaguomsingi ya signal
- `POSIX_SPAWN_SETSIGMASK`: Weka kinyago cha signal
- `POSIX_SPAWN_SETEXEC`: Tekeleza katika mchakato huohuo (kama `execve` yenye chaguo zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anza ikiwa imesimamishwa
- `_POSIX_SPAWN_DISABLE_ASLR`: Anza bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye sehemu za data
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga maelezo yote ya faili kwenye exec(2) kwa chaguomsingi
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Changanya biti za juu za mtelezo wa ASLR bila mpangilio

Zaidi ya hayo, `posix_spawn` hukubali mipangilio ya **`posix_spawnattr`** inayodhibiti vipengele vya mchakato ulioanzishwa, na maingizo ya **`posix_spawn_file_actions`** yanayorekebisha vifafanuzi vya faili.

Mchakato unapokufa, hutuma **msimbo wa kurejesha kwa mchakato mzazi** (mzazi akifa, mzazi mpya huwa PID 1) kupitia signal `SIGCHLD`. Mzazi huhitaji kupata thamani hii kwa kuita `wait4()` au `waitid()`; hadi hilo litokee, mtoto hubaki katika hali ya zombie, ambapo bado huorodheshwa lakini hautumii rasilimali.

### PIDs

PIDs, yaani vitambulisho vya michakato, hutambulisha mchakato wa kipekee. Katika XNU, **PIDs** zina **biti 64**, huongezeka kwa mfuatano na **hazizunguki kamwe** (ili kuzuia matumizi mabaya).

### Vikundi vya Michakato, Sessions na Coalitions

**Michakato** inaweza kuwekwa katika **vikundi** ili kurahisisha kuidhibiti. Kwa mfano, amri zilizo kwenye shell script zitakuwa katika kikundi kimoja cha michakato, hivyo inawezekana **kuzitumia signal pamoja**, kwa mfano kwa kutumia kill.\
Pia inawezekana **kuweka michakato katika sessions**. Mchakato unapoanzisha session (`setsid(2)`), michakato yake watoto huwekwa ndani ya session hiyo, isipokuwa ianzishe session yake yenyewe.

Coalition ni njia nyingine ya kupanga michakato katika Darwin. Mchakato unapojiunga na coalition, unaweza kufikia rasilimali za pamoja, kushiriki ledger au kukabiliwa na Jetsam. Coalitions zina majukumu tofauti: Kiongozi, huduma ya XPC, Extension.

### Vitambulisho na Personae

Kila mchakato huwa na **vitambulisho** vinavyo **bainisha ruhusa zake** katika mfumo. Kila mchakato huwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa unaweza kuwa mwanachama wa vikundi kadhaa).\
Pia inawezekana kubadilisha kitambulisho cha mtumiaji na kikundi ikiwa faili ya binary ina biti ya `setuid/setgid`.\
Kuna vitendaji kadhaa vya **kuweka uids/gids mpya**.

Syscall **`persona`** hutoa seti **mbadala** ya **vitambulisho**. Kuchukua persona kunamaanisha kutumia uid, gid na uanachama wa vikundi vyake **kwa wakati mmoja**. Katika [**msimbo wa chanzo**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:

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

1. **POSIX Threads (pthreads):** macOS inasaidia POSIX threads (`pthreads`), ambazo ni sehemu ya API sanifu ya threading kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana kwenye `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatokana na mradi wa `libpthread` unaopatikana hadharani. Maktaba hii hutoa vitendaji vinavyohitajika kuunda na kusimamia threads.
2. **Kuunda Threads:** Kazi ya `pthread_create()` hutumika kuunda threads mpya. Kwa ndani, kazi hii huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini inayohusu kernel ya XNU (kernel ambayo macOS imejengwa juu yake). System call hii hupokea flags mbalimbali zinazotokana na `pthread_attr` (sifa) zinazoainisha tabia ya thread, ikijumuisha sera za upangaji ratiba na ukubwa wa stack.
   - **Ukubwa Chaguomsingi wa Stack:** Ukubwa chaguomsingi wa stack kwa threads mpya ni KB 512, ambao unatosha kwa shughuli za kawaida lakini unaweza kurekebishwa kupitia sifa za thread ikiwa nafasi zaidi au kidogo inahitajika.
3. **Uanzishaji wa Thread:** Kazi ya `__pthread_init()` ni muhimu wakati wa kusanidi thread; hutumia hoja ya `env[]` kuchanganua environment variables zinazoweza kujumuisha maelezo kuhusu mahali stack ilipo na ukubwa wake.

#### Kusitisha Thread katika macOS

1. **Kumaliza Threads:** Kwa kawaida, threads husitishwa kwa kuita `pthread_exit()`. Kazi hii huruhusu thread kutoka kwa usafi, ikifanya usafishaji unaohitajika na kuiruhusu thread kutuma thamani ya kurudisha kwa threads zozote zinazojiunga nayo.
2. **Usafishaji wa Thread:** `pthread_exit()` inapoitwa, kazi ya `pthread_terminate()` huanzishwa; kazi hii hushughulikia kuondoa miundo yote inayohusishwa na thread. Hutoa Mach thread ports (Mach ni mfumo mdogo wa mawasiliano katika kernel ya XNU) na kuita `bsdthread_terminate`, syscall inayoondoa miundo ya kiwango cha kernel inayohusishwa na thread.

#### Mbinu za Usawazishaji

Ili kusimamia ufikiaji wa rasilimali zinazoshirikiwa na kuepuka race conditions, macOS hutoa primitives kadhaa za usawazishaji. Hizi ni muhimu katika mazingira ya multi-threading ili kuhakikisha uadilifu wa data na uthabiti wa mfumo:

1. **Mutexes:**
   - **Regular Mutex (Sahihi: 0x4D555458):** Mutex ya kawaida yenye ukubwa wa kumbukumbu wa baiti 60 (baiti 56 za mutex na baiti 4 za sahihi).
   - **Fast Mutex (Sahihi: 0x4d55545A):** Inafanana na mutex ya kawaida lakini imeboreshwa kwa shughuli za haraka zaidi; pia ina ukubwa wa baiti 60.
2. **Condition Variables:**
   - Hutumika kusubiri hali fulani zitokee; zina ukubwa wa baiti 44 (baiti 40 pamoja na baiti 4 za sahihi).
   - **Condition Variable Attributes (Sahihi: 0x434e4441):** Sifa za usanidi wa condition variables, zenye ukubwa wa baiti 12.
3. **Once Variable (Sahihi: 0x4f4e4345):**
   - Huhakikisha kwamba kipande cha msimbo wa uanzishaji kinatekelezwa mara moja tu. Kina ukubwa wa baiti 12.
4. **Read-Write Locks:**
   - Huwezesha wasomaji wengi au mwandishi mmoja kutumia kwa wakati mmoja, na kurahisisha ufikiaji bora wa data inayoshirikiwa.
   - **Read Write Lock (Sahihi: 0x52574c4b):** Ina ukubwa wa baiti 196.
   - **Read Write Lock Attributes (Sahihi: 0x52574c41):** Sifa za read-write locks, zenye ukubwa wa baiti 20.

> [!TIP]
> Baiti 4 za mwisho za vitu hivyo hutumika kugundua overflow.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** katika muktadha wa faili za Mach-O (umbizo la executable katika macOS) hutumika kutangaza vigezo maalum kwa **kila thread** katika programu ya multi-threaded. Hii huhakikisha kwamba kila thread ina nakala yake tofauti ya kigezo, na hivyo kutoa njia ya kuepuka migongano na kudumisha uadilifu wa data bila kuhitaji mbinu za wazi za usawazishaji kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza kigezo cha thread-local kwa kutumia neno kuu **`__thread`**. Hivi ndivyo linavyofanya kazi katika mfano wako:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Kipande hiki kinafafanua `tlv_var` kama kigeu cha thread-local. Kila thread inayoendesha msimbo huu itakuwa na `tlv_var` yake, na mabadiliko yanayofanywa na thread moja kwenye `tlv_var` hayataathiri `tlv_var` ya thread nyingine.

Katika binary ya Mach-O, data inayohusiana na thread-local variables hupangwa katika sehemu maalum:

- **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu thread-local variables, kama vile aina zake na hali ya uanzishaji.
- **`__DATA.__thread_bss`**: Sehemu hii hutumika kwa thread-local variables ambazo hazijaanzishwa waziwazi. Ni eneo la kumbukumbu lililotengwa kwa data inayoanzishwa kwa thamani sifuri.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ili kudhibiti thread-local variables thread inapotoka. API hii hukuwezesha **kusajili destructors**—functions maalum zinazofuta data ya thread-local thread inapokoma.

### Vipaumbele vya Thread

Kuelewa vipaumbele vya thread kunahusisha kuchunguza jinsi mfumo wa uendeshaji unavyoamua ni thread zipi za kuendesha na wakati gani. Uamuzi huu huathiriwa na kiwango cha kipaumbele kilichowekwa kwa kila thread. Katika macOS na mifumo inayofanana na Unix, hili hushughulikiwa kwa kutumia dhana kama `nice`, `renice`, na madarasa ya Quality of Service (QoS).

#### Nice na Renice

1. **Nice:**
   - Thamani ya `nice` ya process ni nambari inayoathiri kipaumbele chake. Kila process ina thamani ya nice kuanzia -20 (kipaumbele cha juu zaidi) hadi 19 (kipaumbele cha chini zaidi). Thamani chaguomsingi ya nice wakati process inapoanzishwa kwa kawaida ni 0.
   - Thamani ndogo ya nice (iliyo karibu zaidi na -20) huifanya process iwe "ya kujitanguliza" zaidi, na kuipa muda mwingi zaidi wa CPU ikilinganishwa na process nyingine zenye thamani kubwa zaidi za nice.
2. **Renice:**
   - `renice` ni amri inayotumika kubadilisha thamani ya nice ya process ambayo tayari inaendeshwa. Inaweza kutumika kurekebisha kipaumbele cha process wakati inaendelea, kwa kuongeza au kupunguza mgao wake wa muda wa CPU kulingana na thamani mpya za nice.
   - Kwa mfano, ikiwa process inahitaji rasilimali zaidi za CPU kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Madarasa ya Quality of Service (QoS)

Madarasa ya QoS ni mbinu ya kisasa zaidi ya kushughulikia vipaumbele vya thread, hasa katika mifumo kama macOS inayotumia **Grand Central Dispatch (GCD)**. Madarasa ya QoS huwawezesha developers **kuainisha** kazi katika viwango tofauti kulingana na umuhimu au uharaka wake. macOS hudhibiti uwekaji wa vipaumbele vya thread kiotomatiki kulingana na madarasa haya ya QoS:

1. **User Interactive:**
   - Darasa hili ni la kazi zinazoingiliana na mtumiaji kwa wakati huo au zinazohitaji matokeo ya haraka ili kutoa uzoefu mzuri kwa mtumiaji. Kazi hizi hupewa kipaumbele cha juu zaidi ili kiolesura kiendelee kuitikia (kwa mfano, animations au ushughulikiaji wa matukio).
2. **User Initiated:**
   - Kazi anazoanzisha mtumiaji na kutarajia matokeo ya haraka, kama vile kufungua document au kubofya kitufe kinachohitaji hesabu. Kazi hizi zina kipaumbele cha juu, lakini ziko chini ya User Interactive.
3. **Utility:**
   - Kazi hizi huchukua muda mrefu na kwa kawaida huonyesha kiashirio cha maendeleo (kwa mfano, kupakua faili au kuingiza data). Kipaumbele chake ni cha chini kuliko cha kazi zilizoanzishwa na mtumiaji, na hazihitaji kukamilika mara moja.
4. **Background:**
   - Darasa hili ni la kazi zinazoendeshwa chinichini na hazionekani kwa mtumiaji. Kazi hizi zinaweza kuwa kuorodhesha, kusawazisha data, au kuhifadhi nakala. Zina kipaumbele cha chini zaidi na athari ndogo kwa utendaji wa mfumo.

Kwa kutumia madarasa ya QoS, developers hawahitaji kudhibiti nambari halisi za kipaumbele; badala yake, huzingatia aina ya kazi, na mfumo huboresha rasilimali za CPU ipasavyo.

Zaidi ya hayo, kuna **sera tofauti za upangaji wa thread** zinazobainisha seti ya vigezo vya upangaji ambavyo scheduler itazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hili linaweza kuwa na manufaa katika mashambulizi ya race condition.

## Matumizi Mabaya ya Process za macOS

macOS hutoa mbinu nyingi za **process kuingiliana, kuwasiliana na kushiriki data**. Ingawa mbinu hizi ni muhimu kwa uendeshaji wa kawaida wa mfumo, washambuliaji wanaweza kuzitumia vibaya kwa injection, utekelezaji wa code, au ufikiaji wa data.

### Library Injection

Library Injection ni mbinu ambapo mshambuliaji **hulazimisha process kupakia library hasidi**. Ikishaingizwa, library huendeshwa katika muktadha wa process lengwa, na kumpa mshambuliaji ruhusa na ufikiaji sawa na wa process hiyo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking huhusisha **kunasa miito ya functions** au ujumbe ndani ya code ya software. Kwa kuweka hooks kwenye functions, mshambuliaji anaweza **kubadilisha tabia** ya process, kuchunguza data nyeti, au hata kudhibiti mtiririko wa utekelezaji.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ukurasa huu unahusu metadata ya ARM64 unwind, masharti ya PAC ya arm64e, na call chains za kubuni.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) inarejelea mbinu tofauti ambazo process tofauti hutumia **kushiriki na kubadilishana data**. Ingawa IPC ni msingi wa programu nyingi halali, inaweza pia kutumiwa vibaya kuvuruga utengano wa process, kuvuja kwa taarifa nyeti, au kutekeleza vitendo visivyoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Programu za Electron zinazoendeshwa zikiwa na env variables maalum zinaweza kuwa hatarini kwa process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kutekeleza **man in the browser attack**, inayowezesha kuiba vitufe vilivyobonyezwa, traffic, cookies, kuingiza scripts kwenye kurasa...


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Faili za NIB **hufafanua vipengele vya user interface (UI)** na mwingiliano wake ndani ya programu. Hata hivyo, zinaweza **kutekeleza amri zozote**, na **Gatekeeper haizuii** programu ambayo tayari imetekelezwa kuendeshwa tena ikiwa **faili ya NIB imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya programu zozote kutekeleza amri zozote:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana kuingiza chaguo za JVM kupitia **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, au **`JDK_JAVA_OPTIONS`** na kupakia Java agent au native agent kabla programu haijaanza.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** hupakia JavaScript ya mshambuliaji mapema kupitia `--require` (file) au `--import data:text/javascript,…` (bila file, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** hupakia module kwenye REPL shirikishi, na **`ELECTRON_RUN_AS_NODE`** huwasha tena yote haya kwenye Electron binaries.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana kuingiza code kwenye programu za .NET kupitia **`DOTNET_STARTUP_HOOKS`** kabla ya `Main`, au kwa kutumia vibaya utendaji wa debugging wa .NET wakati masharti yake ya awali yametimizwa.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash isiyo shirikishi husoma **`BASH_ENV`**; POSIX shells shirikishi husoma **`ENV`**; zsh husoma **`$ZDOTDIR/.zshenv`**; na fish husoma mipangilio iliyo chini ya **`XDG_CONFIG_HOME`** au **`XDG_DATA_DIRS`**. Kila moja inaweza kutekeleza faili ya startup inayodhibitiwa kabla ya amri iliyokusudiwa. Bash pia huendesha command substitution iliyowekwa kwenye **`PS4`** kila xtrace inapowashwa (kwa mfano, kupitia **`SHELLOPTS=xtrace`** iliyorithiwa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Kuanzisha `/bin/zsh -s` husababisha shell kusoma program kutoka standard input. Kwa hiyo, downloader inayohamisha document iliyopangwa lakini isiyoaminika hadi stdin ya child bila kuichanganua kwanza, hugeuza document nzima kuwa chanzo cha shell. Loader moja iliyozingatiwa ilipitisha faili ya umma ya iCalendar kupitia anonymous pipe, mstari baada ya mstari. Metadata ya kalenda ilishindwa kutumika kama amri, lakini zsh iliendelea hadi ilipofikia mistari inayoweza kutekelezwa iliyowekwa baada ya `DESCRIPTION:`. Mistari hiyo ilipakua na kuanzisha application bundle iliyofuata. Aina ya maudhui iliyotarajiwa na hosting inayoaminika ya carrier havikufanya hili kuwa salama; mpaka hatari ulikuwa kupitisha bytes zake kwa interpreter.<sup>[[5]](#references)</sup>

Hatua zinazohusiana zimeelezwa katika [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), na [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** au **`PHP_INI_SCAN_DIR`** zinaweza kupakia mipangilio ya PHP inayodhibitiwa, ambayo **`auto_prepend_file`** yake hutekelezwa kabla ya target script.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Lua interpreter inayojitegemea hutekeleza code au `@file` kutoka **`LUA_INIT`** (au toleo lake maalum) kabla ya kushughulikia target script.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** na **`R_PROFILE`** huelekeza upya startup profiles zenye R code. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** pamoja na njia ya R library vinaweza kutumika badala yake kupakia kiotomatiki package iliyosakinishwa.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** huelekeza upya depot ambayo `config/startup.jl` yake hutekelezwa kiotomatiki.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`**, au **`ERL_ZFLAGS`** zinaweza kuingiza expression ya Erlang VM **`-eval`** bila kuhitaji payload file; workloads za Elixir kwa kawaida huanzisha VM hiyo hiyo.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** na **`OCTAVE_VERSION_INITFILE`** huelekeza upya startup scripts za Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` ni programu ya .NET inayotumika kwenye majukwaa mbalimbali, kwa hiyo environment variables kadhaa zinaweza kusababisha utekelezaji kabla ya amri: **`XDG_CONFIG_HOME`** huelekeza upya profile scripts zinazoendeshwa wakati wa startup, **`PSModulePath`** huteka u-pakiaji otomatiki wa module (`.psm1` iliyowekwa huendeshwa wakati wa import na inaweza kufunika cmdlets zilizojengewa ndani), na variables za .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** na **`DOTNET_STARTUP_HOOKS`** hupakia code ya mshambuliaji kwenye process kabla ya `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Angalia njia tofauti za kufanya Perl script itekeleze code yoyote katika:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Pia inawezekana kutumia vibaya env variables za ruby (**`RUBYOPT`**, **`RUBYLIB`**) ili kufanya scripts zozote zitekeleze code yoyote:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Mlolongo wa standard library wa **`PYTHONWARNINGS`** na **`BROWSER`** unaweza kutekeleza amri wakati warning-filter inachanganuliwa. Njia mbadala inayotumia file huweka `sitecustomize.py` kwenye **`PYTHONPATH`** ili uanzishaji wa kawaida wa `site` uiingize kabla ya target script. **`PYTHONBREAKPOINT`** huendesha callable/module iliyochaguliwa code inapofika kwenye `breakpoint()`. Variables zinazotumika katika mazingira shirikishi pekee, kama **`PYTHONSTARTUP`**, zina matumizi finyu zaidi.

Kumbuka kuwa executables zilizokompailiwa kwa **`pyinstaller`** hazitatumia environment variables hizi hata kama zinaendeshwa kwa kutumia embedded python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (na fallback yake ya `EXINIT`) hutekelezwa kama Ex commands wakati wa startup ya kawaida, kwa hiyo `:!cmd` / `:call system(...)` husababisha code execution mwathiriwa anapofungua Vim/Neovim katika mazingira yanayodhibitiwa:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Kando na hili, Homebrew mara nyingi husakinisha Python chini ya `/opt/homebrew`, ambako wanachama wa kundi la ndani la `admin` wanaweza kuweza kubadilisha launcher. Huku ni kuteka binary inayoweza kuandikwa, si injection kupitia environment variable; hakiki umiliki na ACLs kabla ya kudhani kuwa kuna uwezekano wa kutumiwa vibaya.


## Utambuzi

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni programu huria inayotumia **EndpointSecurity** kutambua na kuzuia process injection. Ni rejeleo zuri la ishara zinazoweza kuonekana kupitia Endpoint Security, kwa kuwa hutoa tahadhari kuhusu:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** wakati wa process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- Miito ya **`task_for_pid`** — process moja ikiomba task port ya nyingine, ambayo ni sharti la awali la kuingiza code ndani yake.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, ambazo huanzisha programu ya Electron katika hali ya debug na kumruhusu yeyote kuunganishwa nayo na kuendesha code ndani yake.<sup>[[3]](#references)</sup>
- **Uundaji wa symlink/hardlink kati ya viwango tofauti vya ruhusa** — mbinu ya kawaida ya "weka link kama mtumiaji wa kawaida, kisha ielekeze kwenye eneo lenye ruhusa za juu". Kumbuka kuwa **symlinks zinaweza kutoa tahadhari lakini haziwezi kuzuiwa**: EndpointSecurity haiwezi kuona mahali link inapoelekeza kabla ya kuundwa.

### Miito inayofanywa na process nyingine

Katika [**chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kujifunza jinsi ya kutumia function **`task_name_for_pid`** kupata taarifa kuhusu **process nyingine zinazoingiza code kwenye process**, kisha kupata taarifa kuhusu process hiyo nyingine.<sup>[[4]](#references)</sup>

Kumbuka kuwa ili kuita function hiyo, unahitaji kuwa na **uid sawa** na ile inayoendesha process au kuwa **root** (na hurejesha taarifa kuhusu process, si njia ya kuingiza code).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — ugunduzi huria wa macOS process-injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — mfumo wa EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Kwa nini programu za Electron haziwezi kuhifadhi siri zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Kutambua marekebisho ya task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Toleo jipya la MacSync macOS stealer linalenga wapenda crypto na developers](https://securelist.com/macsync-new-version/121383/)
