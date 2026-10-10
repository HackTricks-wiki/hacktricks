# Matumizi Mabaya ya Michakato ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi kuhusu Michakato

Mchakato ni mfano wa programu inayotekelezwa. Hata hivyo, michakato haiendeshi code; threads ndizo zinazoendesha code. Kwa hiyo, **michakato ni vyombo tu vya kuendeshea threads**, vinavyotoa kumbukumbu, descriptors, ports, ruhusa...

Kijadi, michakato ilianzishwa ndani ya michakato mingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala halisi ya mchakato wa sasa. Kisha **child process** kwa kawaida ingeita **`execve`** ili kupakia programu mpya na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kufanya mchakato huu uwe wa haraka zaidi bila kunakili kumbukumbu.\
Kisha **`posix_spawn`** ilianzishwa, ikiunganisha **`vfork`** na **`execve`** katika mwito mmoja na kukubali flags:

- `POSIX_SPAWN_RESETIDS`: Weka upya effective ids ziwe real ids
- `POSIX_SPAWN_SETPGROUP`: Weka uhusiano wa process group
- `POSUX_SPAWN_SETSIGDEF`: Weka tabia chaguomsingi ya signal
- `POSIX_SPAWN_SETSIGMASK`: Weka signal mask
- `POSIX_SPAWN_SETEXEC`: Tekeleza ndani ya mchakato huohuo (kama `execve` yenye chaguo zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anzisha katika hali ya kusimamishwa
- `_POSIX_SPAWN_DISABLE_ASLR`: Anzisha bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga file descriptions zote kwenye exec(2) kwa chaguomsingi
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Fanya randomize ya high bits za ASLR slide

Zaidi ya hayo, `posix_spawn` hukubali mipangilio ya **`posix_spawnattr`** inayodhibiti vipengele vya mchakato unaoanzishwa, na maingizo ya **`posix_spawn_file_actions`** yanayorekebisha file descriptors.

Mchakato unapokufa, hutuma **return code kwa parent process** (ikiwa parent imekufa, parent mpya ni PID 1) kupitia signal `SIGCHLD`. Parent inahitaji kupata thamani hii kwa kuita `wait4()` au `waitid()`. Hadi hilo lifanyike, child hubaki katika hali ya zombie, ambapo bado imeorodheshwa lakini haitumii rasilimali.

### PIDs

PIDs, yaani process identifiers, hutambulisha mchakato wa kipekee. Katika XNU, **PIDs** zina **64bits**, huongezeka mfululizo na **hazifiki mwisho kisha kuanza upya** (ili kuepuka matumizi mabaya).

### Process Groups, Sessions na Coalitions

**Michakato** inaweza kuwekwa katika **groups** ili iwe rahisi kuisimamia. Kwa mfano, amri katika shell script zitakuwa kwenye process group moja, hivyo inawezekana **kuzitumia signal pamoja**, kwa mfano kwa kutumia kill.\
Pia inawezekana **kuweka michakato katika sessions**. Mchakato unapoanzisha session (`setsid(2)`), michakato ya watoto huwekwa ndani ya session hiyo, isipokuwa ianzishe session yake yenyewe.

Coalition ni njia nyingine ya kuweka michakato katika groups kwenye Darwin. Mchakato unapojiunga na coalition, hupata ufikiaji wa rasilimali za pool, hushiriki ledger au hukabiliwa na Jetsam. Coalitions zina roles tofauti: Leader, XPC service, Extension.

### Credentials na Personae

Kila mchakato huwa na **credentials** zinazotambua **privileges zake** kwenye mfumo. Kila mchakato huwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa unaweza kuwa mwanachama wa groups kadhaa).\
Pia inawezekana kubadilisha user na group id ikiwa binary ina bit ya `setuid/setgid`.\
Kuna functions kadhaa za **kuweka uids/gids mpya**.

Syscall **`persona`** hutoa seti **mbadala** ya **credentials**. Kuchukua persona kunamaanisha kutumia uid, gid na uanachama wake wa groups **kwa wakati mmoja**. Katika [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:

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

## Taarifa za Msingi kuhusu Nyuzi

1. **POSIX Threads (pthreads):** macOS inasaidia POSIX threads (`pthreads`), ambazo ni sehemu ya API ya kawaida ya threading kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana katika `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatokana na mradi wa `libpthread` unaopatikana hadharani. Maktaba hii hutoa functions zinazohitajika kuunda na kusimamia nyuzi.
2. **Kuunda Nyuzi:** Function ya `pthread_create()` hutumika kuunda nyuzi mpya. Ndani yake, function hii huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini inayohusu kernel ya XNU pekee (kernel ambayo macOS imejengwa juu yake). System call hii hupokea flags mbalimbali zinazotokana na `pthread_attr` (sifa), zinazobainisha tabia ya nyuzi, ikiwemo sera za kupanga ratiba na ukubwa wa stack.
   - **Ukubwa Chaguo-msingi wa Stack:** Ukubwa chaguo-msingi wa stack kwa nyuzi mpya ni 512 KB, ambao unatosha kwa shughuli za kawaida, lakini unaweza kurekebishwa kupitia sifa za nyuzi ikiwa nafasi zaidi au kidogo inahitajika.
3. **Kuanzisha Nyuzi:** Function ya `__pthread_init()` ni muhimu wakati wa kuanzisha nyuzi. Hutumia hoja ya `env[]` kuchanganua vigeu vya mazingira ambavyo vinaweza kujumuisha maelezo kuhusu eneo na ukubwa wa stack.

#### Kusitisha Nyuzi katika macOS

1. **Kumaliza Nyuzi:** Kwa kawaida, nyuzi husitishwa kwa kuita `pthread_exit()`. Function hii huruhusu nyuzi kumaliza kazi kwa usahihi, kufanya usafishaji unaohitajika na kurudisha thamani ya matokeo kwa nyuzi zozote zinazojiunga nayo.
2. **Usafishaji wa Nyuzi:** Baada ya kuita `pthread_exit()`, function ya `pthread_terminate()` huitwa ili kuondoa miundo yote inayohusishwa na nyuzi. Huondoa Mach thread ports (Mach ni mfumo mdogo wa mawasiliano katika kernel ya XNU) na kuita `bsdthread_terminate`, syscall inayoondoa miundo ya kiwango cha kernel inayohusishwa na nyuzi hiyo.

#### Mbinu za Usawazishaji

Ili kusimamia ufikiaji wa rasilimali zinazoshirikiwa na kuepuka race conditions, macOS hutoa primitives kadhaa za usawazishaji. Hizi ni muhimu katika mazingira ya multi-threading ili kuhakikisha uadilifu wa data na uthabiti wa mfumo:

1. **Mutexes:**
   - **Regular Mutex (Saini: 0x4D555458):** Mutex ya kawaida yenye ukubwa wa kumbukumbu wa bytes 60 (bytes 56 za mutex na bytes 4 za saini).
   - **Fast Mutex (Saini: 0x4d55545A):** Inafanana na mutex ya kawaida lakini imeboreshwa kwa utendaji wa haraka zaidi; pia ina ukubwa wa bytes 60.
2. **Condition Variables:**
   - Hutumika kusubiri hali fulani zitokee, na ina ukubwa wa bytes 44 (bytes 40 pamoja na saini ya bytes 4).
   - **Condition Variable Attributes (Saini: 0x434e4441):** Sifa za usanidi wa condition variables, zenye ukubwa wa bytes 12.
3. **Once Variable (Saini: 0x4f4e4345):**
   - Huhakikisha kuwa kipande cha msimbo wa uanzishaji kinatekelezwa mara moja tu. Kina ukubwa wa bytes 12.
4. **Read-Write Locks:**
   - Huruhusu wasomaji wengi au mwandishi mmoja kwa wakati mmoja, na hivyo kuwezesha ufikiaji bora wa data inayoshirikiwa.
   - **Read Write Lock (Saini: 0x52574c4b):** Ina ukubwa wa bytes 196.
   - **Read Write Lock Attributes (Saini: 0x52574c41):** Sifa za read-write locks, zenye ukubwa wa bytes 20.

> [!TIP]
> Bytes 4 za mwisho za vitu hivi hutumika kugundua overflows.

### Vigeu vya Ndani vya Nyuzi (TLV)

**Thread Local Variables (TLV)** katika muktadha wa faili za Mach-O (muundo wa executables katika macOS) hutumika kutangaza vigeu vinavyohusika na **kila nyuzi** katika programu ya multi-threaded. Hii huhakikisha kuwa kila nyuzi ina nakala yake ya kigeu, na hivyo kutoa njia ya kuepuka migongano na kudumisha uadilifu wa data bila kuhitaji mbinu za wazi za usawazishaji kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza kigeu cha ndani ya nyuzi kwa kutumia neno kuu la **`__thread`**. Hivi ndivyo kinavyofanya kazi katika mfano wako:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Snippet hii inafafanua `tlv_var` kama kigezo cha ndani cha thread. Kila thread inayoendesha msimbo huu itakuwa na `tlv_var` yake, na mabadiliko ambayo thread moja hufanya kwenye `tlv_var` hayataathiri `tlv_var` ya thread nyingine.

Katika binary ya Mach-O, data inayohusiana na vigezo vya ndani vya thread hupangwa katika sehemu maalum:

- **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu vigezo vya ndani vya thread, kama aina zake na hali ya uanzishaji.
- **`__DATA.__thread_bss`**: Sehemu hii hutumika kwa vigezo vya ndani vya thread ambavyo havijaanzishwa waziwazi. Ni sehemu ya kumbukumbu iliyotengwa kwa data inayoanzishwa kwa thamani sifuri.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ya kudhibiti vigezo vya ndani vya thread wakati thread inatoka. API hii huruhusu **kusajili destructors**—kazi maalum zinazofuta data ya ndani ya thread thread inapokoma.

### Vipaumbele vya Thread

Kuelewa vipaumbele vya thread kunahusisha kuangalia jinsi mfumo wa uendeshaji unavyoamua thread zipi zitaendeshwa na lini. Uamuzi huu huathiriwa na kiwango cha kipaumbele kilichopewa kila thread. Katika macOS na mifumo inayofanana na Unix, hili hushughulikiwa kwa kutumia dhana kama `nice`, `renice`, na madarasa ya Quality of Service (QoS).

#### Nice na Renice

1. **Nice:**
   - Thamani ya `nice` ya mchakato ni nambari inayoathiri kipaumbele chake. Kila mchakato una thamani ya nice kuanzia -20 (kipaumbele cha juu zaidi) hadi 19 (kipaumbele cha chini zaidi). Thamani chaguo-msingi ya nice wakati mchakato unapoundwa kwa kawaida ni 0.
   - Thamani ndogo ya nice (iliyo karibu zaidi na -20) huufanya mchakato uwe na ubinafsi zaidi, na kuupa muda mwingi zaidi wa CPU ikilinganishwa na michakato mingine yenye thamani kubwa zaidi za nice.
2. **Renice:**
   - `renice` ni amri inayotumika kubadilisha thamani ya nice ya mchakato ambao tayari unaendeshwa. Hii inaweza kutumika kurekebisha kipaumbele cha michakato wakati programu inaendelea, kwa kuongeza au kupunguza mgao wake wa muda wa CPU kulingana na thamani mpya za nice.
   - Kwa mfano, ikiwa mchakato unahitaji rasilimali zaidi za CPU kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Madarasa ya Quality of Service (QoS)

Madarasa ya QoS ni mbinu ya kisasa zaidi ya kushughulikia vipaumbele vya thread, hasa katika mifumo kama macOS inayotumia **Grand Central Dispatch (GCD)**. Madarasa ya QoS huruhusu watengenezaji **kuainisha** kazi katika viwango tofauti kulingana na umuhimu au uharaka wake. macOS husimamia kiotomatiki upangaji wa vipaumbele vya thread kulingana na madarasa haya ya QoS:

1. **User Interactive:**
   - Darasa hili ni la kazi zinazoingiliana na mtumiaji kwa sasa au zinazohitaji matokeo ya haraka ili kutoa matumizi mazuri kwa mtumiaji. Kazi hizi hupewa kipaumbele cha juu zaidi ili kiolesura kiendelee kuitikia (kwa mfano, uhuishaji au ushughulikiaji wa matukio).
2. **User Initiated:**
   - Kazi zinazoanzishwa na mtumiaji na ambazo mtumiaji anatarajia matokeo yake mara moja, kama kufungua hati au kubofya kitufe kinachohitaji hesabu. Hizi zina kipaumbele cha juu, lakini ziko chini ya User Interactive.
3. **Utility:**
   - Kazi hizi huchukua muda mrefu na kwa kawaida huonyesha kiashiria cha maendeleo (kwa mfano, kupakua faili au kuleta data). Zina kipaumbele cha chini kuliko kazi zilizoanzishwa na mtumiaji na hazihitaji kukamilika mara moja.
4. **Background:**
   - Darasa hili ni la kazi zinazofanya kazi chinichini na hazionekani kwa mtumiaji. Hizi zinaweza kuwa kazi kama kuorodhesha, kusawazisha data au kuhifadhi nakala rudufu. Zina kipaumbele cha chini zaidi na athari ndogo kwa utendaji wa mfumo.

Kwa kutumia madarasa ya QoS, watengenezaji hawahitaji kusimamia nambari halisi za vipaumbele; badala yake, huzingatia aina ya kazi, na mfumo huboresha matumizi ya rasilimali za CPU ipasavyo.

Zaidi ya hayo, kuna **sera tofauti za upangaji wa thread** zinazotumika kubainisha seti ya vigezo vya upangaji ambavyo kipangaji kitazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hii inaweza kuwa na manufaa katika mashambulizi ya race condition.

## macOS Process Abuse

macOS hutoa mbinu nyingi za **michakato kuingiliana, kuwasiliana na kushiriki data**. Ingawa mbinu hizi ni muhimu kwa uendeshaji wa kawaida wa mfumo, washambuliaji wanaweza kuzitumia vibaya kwa injection, utekelezaji wa msimbo au ufikiaji wa data.

### Library Injection

Library Injection ni mbinu ambayo mshambuliaji **hulazimisha mchakato kupakia library hasidi**. Baada ya kuingizwa, library huendeshwa katika muktadha wa mchakato lengwa, na kumpa mshambuliaji ruhusa na ufikiaji sawa na wa mchakato huo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking huhusisha **kunasa simu za function** au ujumbe ndani ya msimbo wa programu. Kwa ku-hook functions, mshambuliaji anaweza **kubadilisha tabia** ya mchakato, kuchunguza data nyeti au hata kudhibiti mtiririko wa utekelezaji.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) hurejelea mbinu tofauti ambazo michakato tofauti hutumia **kushiriki na kubadilishana data**. Ingawa IPC ni muhimu kwa programu nyingi halali, inaweza pia kutumiwa vibaya kuvuruga utengano wa michakato, kuvuja kwa taarifa nyeti au kutekeleza vitendo visivyoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Programu za Electron zinazoendeshwa zikiwa na env variables maalum zinaweza kuwa katika hatari ya process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kutekeleza **man in the browser attack**, inayowezesha kuiba mibofyo ya vitufe, traffic na cookies, kuingiza scripts kwenye kurasa...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Faili za NIB **hufafanua vipengele vya kiolesura cha mtumiaji (UI)** na mwingiliano wake ndani ya programu. Hata hivyo, zinaweza **kutekeleza amri zozote**, na **Gatekeeper haizuii** programu ambayo tayari imeendeshwa kuendeshwa tena ikiwa **faili ya NIB imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya programu zozote kutekeleza amri zozote:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana kuingiza chaguo za JVM kupitia **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, au **`JDK_JAVA_OPTIONS`** na kupakia Java au native agent kabla programu haijaanza.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** hupakia mapema JavaScript ya mshambuliaji kupitia `--require` (file) au `--import data:text/javascript,…` (bila file, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** hupakia module kwenye REPL ya mwingiliano, na **`ELECTRON_RUN_AS_NODE`** huwasha tena uwezo huu wote kwenye Electron binaries.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana kuingiza msimbo kwenye programu za .NET kupitia **`DOTNET_STARTUP_HOOKS`** kabla ya `Main`, au kutumia vibaya utendaji wa debugging wa .NET ikiwa mahitaji yake ya awali yametimizwa.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash isiyoingiliana husoma **`BASH_ENV`**; POSIX shells zinazoingiliana husoma **`ENV`**; zsh husoma **`$ZDOTDIR/.zshenv`**; na fish husoma faili za usanidi zilizo chini ya **`XDG_CONFIG_HOME`** au **`XDG_DATA_DIRS`**. Kila moja inaweza kutekeleza faili ya uanzishaji inayodhibitiwa kabla ya amri iliyokusudiwa. Bash pia huendesha command substitution iliyowekwa kwenye **`PS4`** kila xtrace inapowashwa (kwa mfano, kupitia **`SHELLOPTS=xtrace`** iliyorithiwa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** au **`PHP_INI_SCAN_DIR`** zinaweza kupakia usanidi wa PHP unaodhibitiwa, ambao **`auto_prepend_file`** yake hutekelezwa kabla ya script lengwa.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Lua interpreter inayojitegemea hutekeleza msimbo au `@file` kutoka **`LUA_INIT`** (au toleo lake maalum kwa version) kabla ya kuchakata script lengwa.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** na **`R_PROFILE`** huelekeza kwenye startup profiles zenye msimbo wa R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** pamoja na njia ya library ya R zinaweza badala yake kupakia kiotomatiki package iliyosakinishwa.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** huelekeza kwenye depot ambayo `config/startup.jl` yake hutekelezwa kiotomatiki.

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

`pwsh` ni programu ya .NET inayofanya kazi kwenye mifumo tofauti, kwa hiyo environment variables kadhaa huwezesha utekelezaji kabla ya amri: **`XDG_CONFIG_HOME`** huelekeza upya profile scripts zinazoendeshwa wakati wa uanzishaji, **`PSModulePath`** huteka nyara upakiaji otomatiki wa module (faili ya `.psm1` iliyowekwa hutekelezwa wakati wa import na inaweza kufunika cmdlets zilizojengewa ndani), na variables za .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** na **`DOTNET_STARTUP_HOOKS`** hupakia msimbo wa mshambuliaji kwenye mchakato kabla ya `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Angalia chaguo tofauti zinazoweza kufanya script ya Perl itekeleze msimbo wowote katika:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Pia inawezekana kutumia vibaya ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) ili kufanya scripts zozote zitekeleze msimbo wowote:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Mchanganyiko wa **`PYTHONWARNINGS`** na **`BROWSER`** wa standard library unaweza kutekeleza amri wakati wa uchanganuzi wa warning-filter. Njia mbadala inayotumia file huweka `sitecustomize.py` kwenye **`PYTHONPATH`** ili uanzishaji wa kawaida wa `site` ui-import kabla ya script lengwa. **`PYTHONBREAKPOINT`** huendesha callable/module iliyochaguliwa msimbo unapofikia `breakpoint()`. Variables zinazotumika kwenye mwingiliano pekee, kama **`PYTHONSTARTUP`**, zina matumizi finyu zaidi.

Kumbuka kwamba executables zilizokusanywa kwa **`pyinstaller`** hazitumii environmental variables hizi hata kama zinaendeshwa kwa kutumia python iliyopachikwa.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (na mbadala wake `EXINIT`) hutekelezwa kama Ex commands wakati wa uanzishaji wa kawaida, kwa hiyo `:!cmd` / `:call system(...)` huwezesha utekelezaji wa msimbo mwathiriwa anapofungua Vim/Neovim akiwa na mazingira yaliyodhibitiwa:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Tofauti na hilo, Homebrew mara nyingi husakinisha Python chini ya `/opt/homebrew`, ambapo wanachama wa kundi la ndani la `admin` wanaweza kuwa na uwezo wa kubadilisha launcher. Huu ni utekaji nyara wa binary inayoweza kuandikwa, si injection ya environment variable; hakiki umiliki na ACLs kabla ya kuhitimisha kuwa inaweza kutumiwa vibaya.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni programu ya open-source inayotumia **EndpointSecurity** kugundua na kuzuia process injection. Ni rejea nzuri ya kuelewa ishara zinazoweza kuonekana kupitia Endpoint Security, kwa kuwa hutoa tahadhari kuhusu:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** wakati wa process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- Simu za **`task_for_pid`** — mchakato mmoja ukiomba task port ya mwingine, ambayo ni sharti la awali la kuingiza msimbo ndani yake.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, ambazo huanzisha programu ya Electron katika hali ya debug na kuruhusu mtu yeyote kuunganisha na kutekeleza msimbo ndani yake.<sup>[[3]](#references)</sup>
- **Uundaji wa symlink/hardlink kati ya viwango tofauti vya privilege** — mbinu ya kawaida ya "weka link kama mtumiaji wa kawaida, kisha ielekeze kwenye eneo lenye privilege". Kumbuka kwamba **symlinks zinaweza kusababisha tahadhari lakini haziwezi kuzuiwa**: EndpointSecurity haionyeshi link destination kabla ya uundaji.

### Simu zinazofanywa na michakato mingine

Katika [**chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata maelezo kuhusu jinsi function **`task_name_for_pid`** inavyoweza kutumika kupata taarifa kuhusu **michakato mingine inayoingiza msimbo kwenye mchakato**, na kisha kupata taarifa kuhusu mchakato huo mwingine.<sup>[[4]](#references)</sup>

Kumbuka kwamba ili kuita function hiyo, lazima uwe na **uid sawa** na ile inayoendesha mchakato au uwe **root** (na hurejesha taarifa kuhusu mchakato, si njia ya kuingiza msimbo).

## References

- [1] [Shield — ugunduzi wa process injection kwenye macOS kwa kutumia open-source (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework ya EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Kwa nini programu za Electron haziwezi kuhifadhi siri zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Kugundua marekebisho ya task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
