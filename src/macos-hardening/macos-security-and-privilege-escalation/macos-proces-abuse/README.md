# Matumizi Mabaya ya Michakato ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi kuhusu Michakato

Mchakato ni nakala ya executable inayotekelezwa, lakini michakato haiendeshi code; threads ndizo zinazoendesha. Kwa hiyo, **processes ni kontena tu za threads zinazoendeshwa**, zinazotoa memory, descriptors, ports, permissions...

Kijadi, michakato ilianzishwa ndani ya michakato mingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala kamili ya mchakato wa sasa; kisha **child process** kwa kawaida ingeita **`execve`** kupakia executable mpya na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kuharakisha mchakato huu bila kunakili memory.\
Kisha **`posix_spawn`** ilianzishwa, ikiunganisha **`vfork`** na **`execve`** katika mwito mmoja na kukubali flags:

- `POSIX_SPAWN_RESETIDS`: Weka upya effective ids ziwe real ids
- `POSIX_SPAWN_SETPGROUP`: Weka ushirika wa process group
- `POSUX_SPAWN_SETSIGDEF`: Weka tabia chaguomsingi ya signal
- `POSIX_SPAWN_SETSIGMASK`: Weka signal mask
- `POSIX_SPAWN_SETEXEC`: Tekeleza ndani ya mchakato huohuo (kama `execve` yenye options zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anzisha ikiwa imesimamishwa
- `_POSIX_SPAWN_DISABLE_ASLR`: Anzisha bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga file descriptions zote kwenye exec(2) kwa chaguomsingi
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Fanya high bits za ASLR slide ziwe za nasibu

Zaidi ya hayo, `posix_spawn` hukubali mipangilio ya **`posix_spawnattr`** inayodhibiti vipengele vya mchakato unaozalishwa na maingizo ya **`posix_spawn_file_actions`** yanayobadilisha file descriptors.

Mchakato unapokufa, hutuma **return code kwa parent process** (ikiwa parent imekufa, parent mpya huwa PID 1) kupitia signal `SIGCHLD`. Parent huhitaji kupata thamani hii kwa kuita `wait4()` au `waitid()`. Hadi hilo litokee, child hubaki katika hali ya zombie, ambapo bado huorodheshwa lakini haitumii resources.

### PIDs

PIDs, yaani process identifiers, hutambulisha mchakato wa kipekee. Katika XNU, **PIDs** zina **bits 64**, huongezeka kwa mfululizo na **hazizunguki kamwe** (ili kuzuia matumizi mabaya).

### Process Groups, Sessions na Coalitions

**Michakato** inaweza kuwekwa katika **groups** ili kurahisisha usimamizi wake. Kwa mfano, commands katika shell script zitakuwa katika process group moja, hivyo inawezekana **kuzitumia signal pamoja**, kwa mfano kwa kutumia kill.\
Pia inawezekana **kuweka michakato katika sessions**. Mchakato unapoanzisha session (`setsid(2)`), michakato yake ya watoto huwekwa ndani ya session hiyo, isipokuwa ianzishe session yake yenyewe.

Coalition ni njia nyingine ya kuweka michakato katika groups katika Darwin. Mchakato unapojiunga na coalition, unaweza kufikia shared pool resources, kushiriki ledger au kukabiliwa na Jetsam. Coalitions zina roles tofauti: Leader, XPC service, Extension.

### Credentials na Personae

Kila mchakato huwa na **credentials** **zinazotambulisha privileges zake** katika mfumo. Kila mchakato huwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa unaweza kuwa mwanachama wa groups kadhaa).\
Pia inawezekana kubadilisha user na group id ikiwa binary ina bit ya `setuid/setgid`.\
Kuna functions kadhaa za **kuweka uids/gids mpya**.

Syscall **`persona`** hutoa seti **mbadala** ya **credentials**. Kupitisha persona kunamaanisha kuchukua uid, gid na group memberships zake **kwa pamoja**. Katika [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:

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

1. **POSIX Threads (pthreads):** macOS inatumia POSIX threads (`pthreads`), ambazo ni sehemu ya API ya kawaida ya threading kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana kwenye `/usr/lib/system/libsystem_pthread.dylib`, inayotokana na mradi wa `libpthread` unaopatikana hadharani. Maktaba hii hutoa vitendaji vinavyohitajika kuunda na kudhibiti threads.
2. **Kuunda Threads:** Kazi ya `pthread_create()` hutumika kuunda threads mpya. Ndani yake, kazi hii huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini inayohusu kernel ya XNU (kernel ambayo macOS imejengwa juu yake). System call hii hupokea bendera mbalimbali zinazotokana na `pthread_attr` (sifa), zinazobainisha tabia ya thread, ikijumuisha sera za scheduling na ukubwa wa stack.
   - **Ukubwa Chaguo-msingi wa Stack:** Ukubwa chaguo-msingi wa stack kwa threads mpya ni 512 KB, unaotosha kwa shughuli za kawaida lakini unaweza kurekebishwa kupitia sifa za thread ikiwa nafasi zaidi au kidogo inahitajika.
3. **Uanzishaji wa Thread:** Kazi ya `__pthread_init()` ni muhimu wakati wa usanidi wa thread. Hutumia hoja ya `env[]` kuchanganua environment variables zinazoweza kuwa na maelezo kuhusu eneo na ukubwa wa stack.

#### Kusitishwa kwa Thread katika macOS

1. **Kutoka kwa Threads:** Kwa kawaida, threads husitishwa kwa kuita `pthread_exit()`. Kazi hii huruhusu thread kutoka kwa usafi, kufanya usafishaji unaohitajika na kuruhusu thread kutuma thamani ya kurejesha kwa threads zinazojiunga nayo.
2. **Usafishaji wa Thread:** `pthread_exit()` inapoitwa, kazi ya `pthread_terminate()` hutekelezwa na kushughulikia uondoaji wa miundo yote inayohusishwa na thread. Huondoa Mach thread ports (Mach ni mfumo mdogo wa mawasiliano katika kernel ya XNU) na kuita `bsdthread_terminate`, ambayo ni syscall inayoondoa miundo ya kiwango cha kernel inayohusishwa na thread.

#### Mbinu za Usawazishaji

Ili kudhibiti ufikiaji wa rasilimali zinazoshirikiwa na kuepuka race conditions, macOS hutoa primitives kadhaa za usawazishaji. Hizi ni muhimu katika mazingira ya multi-threading ili kuhakikisha uadilifu wa data na uthabiti wa mfumo:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** Mutex ya kawaida yenye ukubwa wa kumbukumbu wa baiti 60 (baiti 56 za mutex na baiti 4 za signature).
   - **Fast Mutex (Signature: 0x4d55545A):** Inafanana na mutex ya kawaida lakini imeboreshwa kwa shughuli za kasi zaidi; pia ina ukubwa wa baiti 60.
2. **Condition Variables:**
   - Hutumika kusubiri hali fulani zitokee, na ina ukubwa wa baiti 44 (baiti 40 pamoja na signature ya baiti 4).
   - **Condition Variable Attributes (Signature: 0x434e4441):** Sifa za usanidi wa condition variables, zenye ukubwa wa baiti 12.
3. **Once Variable (Signature: 0x4f4e4345):**
   - Huhakikisha kwamba kipande cha msimbo wa uanzishaji kinatekelezwa mara moja tu. Kina ukubwa wa baiti 12.
4. **Read-Write Locks:**
   - Huruhusu readers wengi au writer mmoja kwa wakati mmoja, na kuwezesha ufikiaji bora wa data inayoshirikiwa.
   - **Read Write Lock (Signature: 0x52574c4b):** Ina ukubwa wa baiti 196.
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Sifa za read-write locks, zenye ukubwa wa baiti 20.

> [!TIP]
> Baiti 4 za mwisho za objects hizo hutumika kugundua overflows.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** katika muktadha wa faili za Mach-O (muundo wa executables katika macOS) hutumika kutangaza variables ambazo ni mahususi kwa **kila thread** katika programu ya multi-threaded. Hii huhakikisha kwamba kila thread ina nakala yake tofauti ya variable, na hivyo kutoa njia ya kuepuka migongano na kudumisha uadilifu wa data bila kuhitaji mbinu za wazi za usawazishaji kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza variable ya thread-local kwa kutumia keyword **`__thread`**. Hivi ndivyo inavyofanya kazi katika mfano wako:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Kipande hiki kinafafanua `tlv_var` kama kigezo cha thread-local. Kila thread inayoendesha msimbo huu itakuwa na `tlv_var` yake, na mabadiliko yanayofanywa na thread moja kwenye `tlv_var` hayataathiri `tlv_var` ya thread nyingine.

Katika binary ya Mach-O, data inayohusiana na vigezo vya thread-local hupangwa katika sehemu maalum:

- **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu vigezo vya thread-local, kama vile aina zake na hali ya uanzishaji.
- **`__DATA.__thread_bss`**: Sehemu hii hutumika kwa vigezo vya thread-local ambavyo havijawekewa thamani ya awali waziwazi. Ni eneo la kumbukumbu lililotengwa kwa data inayoanzishwa kwa sifuri.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ya kudhibiti vigezo vya thread-local wakati thread inapotoka. API hii hukuruhusu **kusajili destructors**—vitendaji maalum vinavyosafisha data ya thread-local thread inapokoma.

### Vipaumbele vya Thread

Kuelewa vipaumbele vya thread kunahusisha kuchunguza jinsi mfumo wa uendeshaji unavyoamua thread zitakazoendeshwa na wakati zitakapoendeshwa. Uamuzi huu huathiriwa na kiwango cha kipaumbele kilichowekwa kwa kila thread. Katika macOS na mifumo inayofanana na Unix, hili hushughulikiwa kwa kutumia dhana kama `nice`, `renice`, na madarasa ya Quality of Service (QoS).

#### Nice na Renice

1. **Nice:**
   - Thamani ya `nice` ya process ni nambari inayoathiri kipaumbele chake. Kila process ina thamani ya nice kuanzia -20 (kipaumbele cha juu zaidi) hadi 19 (kipaumbele cha chini zaidi). Thamani chaguomsingi ya nice wakati process inapoundwa kwa kawaida ni 0.
   - Thamani ndogo ya nice (iliyo karibu zaidi na -20) hufanya process iwe na “ubinafsi” zaidi, na kuipa muda zaidi wa CPU ikilinganishwa na process nyingine zenye thamani kubwa zaidi za nice.
2. **Renice:**
   - `renice` ni amri inayotumika kubadilisha thamani ya nice ya process ambayo tayari inaendeshwa. Inaweza kutumiwa kurekebisha kipaumbele cha process kwa nguvu, kuongeza au kupunguza mgao wa muda wake wa CPU kulingana na thamani mpya za nice.
   - Kwa mfano, ikiwa process inahitaji rasilimali zaidi za CPU kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Madarasa ya Quality of Service (QoS)

Madarasa ya QoS ni mbinu ya kisasa zaidi ya kushughulikia vipaumbele vya thread, hasa katika mifumo kama macOS inayotumia **Grand Central Dispatch (GCD)**. Madarasa ya QoS huwawezesha wasanidi **kuainisha** kazi katika viwango tofauti kulingana na umuhimu au uharaka wake. macOS hudhibiti uwekaji wa vipaumbele vya thread kiotomatiki kulingana na madarasa haya ya QoS:

1. **User Interactive:**
   - Darasa hili ni la kazi zinazoingiliana na mtumiaji kwa sasa au zinazohitaji matokeo ya haraka ili kutoa utumiaji mzuri. Kazi hizi hupewa kipaumbele cha juu zaidi ili kiolesura kiendelee kuitikia (kwa mfano, uhuishaji au ushughulikiaji wa matukio).
2. **User Initiated:**
   - Kazi zinazoanzishwa na mtumiaji ambaye anatarajia matokeo ya haraka, kama vile kufungua hati au kubofya kitufe kinachohitaji ukokotoaji. Hizi zina kipaumbele cha juu, lakini ziko chini ya User Interactive.
3. **Utility:**
   - Kazi hizi huchukua muda mrefu na kwa kawaida huonyesha kiashiria cha maendeleo (kwa mfano, kupakua faili au kuingiza data). Zina kipaumbele cha chini kuliko kazi zilizoanzishwa na mtumiaji, na hazihitaji kukamilika mara moja.
4. **Background:**
   - Darasa hili ni la kazi zinazoendeshwa chinichini na hazionekani kwa mtumiaji. Kazi hizi zinaweza kuwa kama uorodheshaji, usawazishaji au nakala rudufu. Zina kipaumbele cha chini zaidi na athari ndogo zaidi kwa utendaji wa mfumo.

Kwa kutumia madarasa ya QoS, wasanidi hawahitaji kudhibiti nambari kamili za kipaumbele; badala yake, huzingatia aina ya kazi, na mfumo huboresha rasilimali za CPU ipasavyo.

Zaidi ya hayo, kuna **sera za upangaji wa thread** tofauti zinazowezesha kubainisha seti ya vigezo vya upangaji ambavyo scheduler itazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Linaweza kuwa na manufaa katika mashambulizi ya race condition.

## Matumizi Mabaya ya Process za macOS

macOS hutoa mifumo mingi ya **process kuingiliana, kuwasiliana na kushiriki data**. Ingawa mifumo hii ni muhimu kwa utendaji wa kawaida wa mfumo, washambuliaji wanaweza kuitumia vibaya kwa injection, utekelezaji wa msimbo au ufikiaji wa data.

### Library Injection

Library Injection ni mbinu ambapo mshambuliaji **hulazimisha process kupakia library hasidi**. Baada ya kudungwa, library huendeshwa katika muktadha wa process lengwa, na kumpa mshambuliaji ruhusa na ufikiaji sawa na wa process hiyo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking inahusisha **kunasa miito ya function** au ujumbe ndani ya msimbo wa programu. Kwa kuweka hook kwenye function, mshambuliaji anaweza **kubadilisha tabia** ya process, kuchunguza data nyeti, au hata kudhibiti mtiririko wa utekelezaji.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ukurasa huu unaeleza metadata ya ARM64 unwind, vikwazo vya PAC vya arm64e, na minyororo ya synthetic call.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) hurejelea mbinu mbalimbali ambazo process tofauti hutumia **kushiriki na kubadilishana data**. Ingawa IPC ni msingi wa programu nyingi halali, inaweza pia kutumiwa vibaya ili kuvunja utengano wa process, kuvuja taarifa nyeti au kutekeleza vitendo visivyoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Programu za Electron zinazoendeshwa zikiwa na vigezo maalum vya env zinaweza kuwa katika hatari ya process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kutekeleza **shambulizi la man in the browser**, linalowezesha kuiba mibofyo ya vitufe, trafiki na cookies, kudunga scripts kwenye kurasa...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Faili za NIB **hufafanua vipengele vya kiolesura cha mtumiaji (UI)** na mwingiliano wake ndani ya programu. Hata hivyo, zinaweza **kutekeleza amri zozote**, na **Gatekeeper haizuii** programu iliyokwishaendeshwa kuendeshwa tena ikiwa **faili ya NIB imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya programu zozote zitekeleze amri zozote:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana kudunga chaguo za JVM kupitia **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, au **`JDK_JAVA_OPTIONS`**, na kupakia Java agent au native agent kabla ya programu kuanza.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** hupakia mapema JavaScript ya mshambuliaji kupitia `--require` (faili) au `--import data:text/javascript,…` (bila faili, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** hupakia module kwenye REPL shirikishi, na **`ELECTRON_RUN_AS_NODE`** huwasha tena yote haya kwenye binary za Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana kudunga msimbo kwenye programu za .NET kupitia **`DOTNET_STARTUP_HOOKS`** kabla ya `Main`, au kutumia vibaya utendaji wa debugging wa .NET wakati masharti yake ya awali yametimizwa.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash isiyo shirikishi husoma **`BASH_ENV`**; shell shirikishi za POSIX husoma **`ENV`**; zsh husoma **`$ZDOTDIR/.zshenv`**; na fish husoma usanidi ulio chini ya **`XDG_CONFIG_HOME`** au **`XDG_DATA_DIRS`**. Kila moja inaweza kutekeleza faili ya uanzishaji inayodhibitiwa kabla ya amri iliyokusudiwa. Bash pia hutekeleza command substitution iliyowekwa kwenye **`PS4`** kila xtrace inapowashwa (kwa mfano, kupitia **`SHELLOPTS=xtrace`** iliyorithiwa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** au **`PHP_INI_SCAN_DIR`** inaweza kupakia usanidi wa PHP unaodhibitiwa, ambao **`auto_prepend_file`** yake hutekelezwa kabla ya script lengwa.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Lua interpreter ya kujitegemea hutekeleza msimbo au `@file` kutoka **`LUA_INIT`** (au toleo lake mahususi) kabla ya kuchakata script lengwa.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** na **`R_PROFILE`** huelekeza kwenye profile za uanzishaji zenye msimbo wa R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** pamoja na njia ya library ya R vinaweza badala yake kupakia kiotomatiki package iliyosakinishwa.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** huelekeza kwenye depot ambayo `config/startup.jl` yake hutekelezwa kiotomatiki.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`**, au **`ERL_ZFLAGS`** zinaweza kudunga expression ya Erlang VM **`-eval`** bila kuhitaji faili ya payload; workloads za Elixir kwa kawaida huanzisha VM hiyo hiyo.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** na **`OCTAVE_VERSION_INITFILE`** huelekeza upya scripts za uanzishaji za Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` ni programu ya .NET ya mifumo mingi, kwa hiyo vigezo kadhaa vya mazingira huwezesha utekelezaji kabla ya amri: **`XDG_CONFIG_HOME`** huelekeza upya scripts za profile zinazoendeshwa wakati wa uanzishaji, **`PSModulePath`** huteka upakiaji wa module kiotomatiki (faili ya `.psm1` iliyopandikizwa huendeshwa wakati wa import na inaweza kufunika cmdlets zilizojengewa ndani), na vigezo vya .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** na **`DOTNET_STARTUP_HOOKS`** hupakia msimbo wa mshambuliaji kwenye process kabla ya `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Angalia chaguo mbalimbali za kufanya script ya Perl itekeleze msimbo wowote kupitia:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Pia inawezekana kutumia vibaya vigezo vya mazingira vya ruby (**`RUBYOPT`**, **`RUBYLIB`**) ili kufanya scripts zozote zitekeleze msimbo wowote:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Mnyororo wa standard library wa **`PYTHONWARNINGS`** na **`BROWSER`** unaweza kutekeleza amri wakati wa kuchanganua warning-filter. Njia mbadala inayotumia faili huweka `sitecustomize.py` kwenye **`PYTHONPATH`**, ili uanzishaji wa kawaida wa `site` ui-import kabla ya script lengwa. **`PYTHONBREAKPOINT`** huendesha callable/module iliyochaguliwa msimbo unapofikia `breakpoint()`. Vigezo vinavyotumika katika hali shirikishi pekee, kama **`PYTHONSTARTUP`**, vina wigo mdogo wa matumizi.

Kumbuka kuwa executable zilizokusanywa kwa **`pyinstaller`** hazitatumia vigezo hivi vya mazingira hata kama zinaendeshwa kwa kutumia Python iliyopachikwa.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (na mbadala wake `EXINIT`) hutekelezwa kama amri za Ex wakati wa uanzishaji wa kawaida, kwa hiyo `:!cmd` / `:call system(...)` husababisha utekelezaji wa msimbo mwathiriwa anapofungua Vim/Neovim akiwa na mazingira yaliyodhibitiwa:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Kando na hilo, Homebrew kwa kawaida husakinisha Python chini ya `/opt/homebrew`, ambapo wanachama wa kundi la `admin` la ndani wanaweza kuweza kubadilisha launcher. Huu ni utekaji wa binary inayoweza kuandikwa, si injection kupitia vigezo vya mazingira; hakiki umiliki na ACL kabla ya kuuchukulia kuwa unaweza kutumiwa vibaya.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni programu huria inayotegemea **EndpointSecurity**, inayotambua na kuzuia process injection. Ni rejeleo zuri la ishara zinazoweza kuonekana kupitia Endpoint Security, kwani hutoa tahadhari kuhusu:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Vigezo vya mazingira vya injection** wakati wa process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- Miito ya **`task_for_pid`** — process moja ikiomba task port ya nyingine, jambo ambalo ni sharti la kuidunga.
- **Hoja za Electron debugging** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, ambazo huanzisha programu ya Electron katika hali ya debug na kuruhusu mtu yeyote kujiunganisha na kutekeleza msimbo ndani yake.<sup>[[3]](#references)</sup>
- **Uundaji wa symlink/hardlink kati ya viwango tofauti vya ruhusa** — mbinu ya kawaida ya “tengeneza link kama mtumiaji wa kawaida, ielekeze kwenye eneo lenye ruhusa za juu.” Kumbuka kuwa **symlink zinaweza kutambuliwa na kutoa tahadhari, lakini haziwezi kuzuiwa**: EndpointSecurity haionyeshi lengwa la link kabla ya kuundwa.

### Miito inayofanywa na process nyingine

Katika [**chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata maelezo ya jinsi function **`task_name_for_pid`** inavyoweza kutumiwa kupata taarifa kuhusu **process nyingine zinazodunga msimbo kwenye process**, kisha kupata taarifa kuhusu process hiyo nyingine.<sup>[[4]](#references)</sup>

Kumbuka kuwa ili kuita function hiyo, lazima uwe na **uid sawa** na ile ya process inayoendesha au uwe **root** (na hurejesha taarifa kuhusu process, si njia ya kudunga msimbo).

## References

- [1] [Shield — utambuzi huria wa macOS process-injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — mfumo wa EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Kwa nini programu za Electron haziwezi kuhifadhi siri zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Kutambua mabadiliko ya task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
