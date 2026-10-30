# Matumizi Mabaya ya Michakato ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi za Michakato

Mchakato ni mfano wa programu inayotekelezwa, hata hivyo michakato haiendeshi msimbo; nyuzi ndizo zinazofanya hivyo. Kwa hiyo, **michakato ni kontena tu za nyuzi zinazoendeshwa** zinazotoa kumbukumbu, vidhibiti, milango, ruhusa...

Kwa kawaida, michakato ilianzishwa ndani ya michakato mingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala halisi ya mchakato wa sasa, kisha **mchakato mtoto** kwa kawaida ungeita **`execve`** ili kupakia programu mpya inayotekelezeka na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kufanya mchakato huu uwe wa haraka zaidi bila kunakili kumbukumbu.\
Kisha **`posix_spawn`** ilianzishwa, ikiunganisha **`vfork`** na **`execve`** katika mwito mmoja na kukubali alama hizi:

- `POSIX_SPAWN_RESETIDS`: Weka upya vitambulisho halisi vya mtumiaji na kikundi kama vitambulisho vinavyotumika
- `POSIX_SPAWN_SETPGROUP`: Weka uhusiano wa kikundi cha mchakato
- `POSUX_SPAWN_SETSIGDEF`: Weka tabia chaguomsingi ya ishara
- `POSIX_SPAWN_SETSIGMASK`: Weka kinyago cha ishara
- `POSIX_SPAWN_SETEXEC`: Tekeleza katika mchakato huohuo (kama `execve` yenye chaguo zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anza ikiwa imesimamishwa
- `_POSIX_SPAWN_DISABLE_ASLR`: Anza bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye sehemu za data
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga maelezo yote ya faili kwenye exec(2) kwa chaguomsingi
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Fanya biti za juu za ASLR slide ziwe nasibu

Zaidi ya hayo, `posix_spawn` inakubali mipangilio ya **`posix_spawnattr`** inayodhibiti vipengele vya mchakato ulioanzishwa na maingizo ya **`posix_spawn_file_actions`** yanayorekebisha vidhibiti vya faili.

Mchakato unapokufa hutuma **msimbo wa matokeo kwa mchakato mzazi** (mzazi akifa, mzazi mpya huwa PID 1) kupitia ishara `SIGCHLD`. Mzazi anahitaji kupata thamani hii kwa kuita `wait4()` au `waitid()`, na hadi hilo litokee, mtoto hubaki katika hali ya zombie ambamo bado huorodheshwa lakini hautumii rasilimali.

### PIDs

PIDs, vitambulishi vya michakato, hutambulisha mchakato wa kipekee. Katika XNU, **PIDs** zina **biti 64**, huongezeka kwa mpangilio na **hazizunguki kamwe** (ili kuzuia matumizi mabaya).

### Vikundi vya Michakato, Vipindi na Coalations

**Michakato** inaweza kuwekwa katika **vikundi** ili iwe rahisi kuisimamia. Kwa mfano, amri katika hati ya shell zitakuwa katika kikundi kimoja cha michakato, hivyo inawezekana **kuzitumia ishara pamoja** kwa kutumia kill, kwa mfano.\
Pia inawezekana **kupanga michakato katika vipindi**. Mchakato unapoanzisha kipindi (`setsid(2)`), michakato watoto huwekwa ndani ya kipindi hicho, isipokuwa ianzishe kipindi chake yenyewe.

Coalition ni njia nyingine ya kupanga michakato katika Darwin. Mchakato unaojiunga na coalition huweza kufikia rasilimali za pool, kushiriki ledger au kukabiliwa na Jetsam. Coalations zina majukumu tofauti: Kiongozi, huduma ya XPC, Kiendelezi.

### Vitambulisho na Personae

Kila mchakato huwa na **vitambulisho** vinavyo **tambua mapendeleo yake** katika mfumo. Kila mchakato huwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa unaweza kuwa mwanachama wa vikundi kadhaa).\
Pia inawezekana kubadilisha kitambulisho cha mtumiaji na cha kikundi ikiwa faili inayotekelezeka ina biti ya `setuid/setgid`.\
Kuna vitendaji kadhaa vya **kuweka uid/gid mpya**.

Mfumo wa kuita **`persona`** hutoa seti **mbadala** ya **vitambulisho**. Kukubali persona kunamaanisha kuchukua uid, gid na uanachama wa vikundi vyake **kwa wakati mmoja**. Katika [**msimbo chanzo**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata muundo huu:

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

1. **POSIX Threads (pthreads):** macOS inatumia POSIX threads (`pthreads`), ambazo ni sehemu ya API sanifu ya threading kwa C/C++. Utekelezaji wa pthreads katika macOS unapatikana kwenye `/usr/lib/system/libsystem_pthread.dylib`, inayotokana na mradi wa `libpthread` unaopatikana hadharani. Maktaba hii hutoa functions zinazohitajika kuunda na kudhibiti threads.
2. **Kuunda Threads:** Function ya `pthread_create()` hutumika kuunda threads mpya. Ndani, function hii huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini maalum kwa kernel ya XNU (kernel ambayo macOS imejengwa juu yake). System call hii hupokea flags mbalimbali zinazotokana na `pthread_attr` (attributes) zinazobainisha tabia ya thread, ikiwemo sera za scheduling na ukubwa wa stack.
   - **Ukubwa Chaguomsingi wa Stack:** Ukubwa chaguomsingi wa stack kwa threads mpya ni 512 KB, ambao unatosha kwa shughuli za kawaida lakini unaweza kurekebishwa kupitia thread attributes ikiwa nafasi zaidi au ndogo inahitajika.
3. **Kuanzisha Thread:** Function ya `__pthread_init()` ni muhimu wakati wa kuanzisha thread; hutumia argument ya `env[]` kuchanganua environment variables zinazoweza kujumuisha maelezo kuhusu mahali stack ilipo na ukubwa wake.

#### Kusitisha Threads katika macOS

1. **Kutoka kwenye Threads:** Kwa kawaida, threads husitishwa kwa kuita `pthread_exit()`. Function hii huwezesha thread kutoka kwa usahihi, kufanya usafishaji unaohitajika na kurudisha thamani kwa threads zozote zinazojiunga nayo.
2. **Usafishaji wa Thread:** `pthread_exit()` inapoitiwa, function ya `pthread_terminate()` huitwa na kushughulikia uondoaji wa miundo yote inayohusishwa na thread. Huondoa Mach thread ports (Mach ni mfumo mdogo wa mawasiliano ndani ya kernel ya XNU) na kuita `bsdthread_terminate`, syscall inayoondoa miundo ya kiwango cha kernel inayohusishwa na thread.

#### Mbinu za Usawazishaji

Ili kudhibiti ufikiaji wa rasilimali zinazoshirikiwa na kuepuka race conditions, macOS hutoa primitives kadhaa za synchronization. Hizi ni muhimu katika mazingira ya multi-threading ili kuhakikisha uadilifu wa data na uthabiti wa mfumo:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** Mutex ya kawaida yenye ukubwa wa kumbukumbu wa bytes 60 (bytes 56 za mutex na bytes 4 za signature).
   - **Fast Mutex (Signature: 0x4d55545A):** Inafanana na mutex ya kawaida lakini imeboreshwa kwa utendaji wa haraka zaidi; pia ina ukubwa wa bytes 60.
2. **Condition Variables:**
   - Hutumika kusubiri hali fulani zitokee; zina ukubwa wa bytes 44 (bytes 40 pamoja na signature ya bytes 4).
   - **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes za condition variables, zenye ukubwa wa bytes 12.
3. **Once Variable (Signature: 0x4f4e4345):**
   - Huhakikisha kwamba sehemu ya code ya initialization inatekelezwa mara moja tu. Ina ukubwa wa bytes 12.
4. **Read-Write Locks:**
   - Huruhusu wasomaji wengi au mwandishi mmoja kwa wakati mmoja, na hivyo kuwezesha ufikiaji bora wa data inayoshirikiwa.
   - **Read Write Lock (Signature: 0x52574c4b):** Ina ukubwa wa bytes 196.
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes za read-write locks, zenye ukubwa wa bytes 20.

> [!TIP]
> Bytes 4 za mwisho za objects hizo hutumika kugundua overflows.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** katika muktadha wa faili za Mach-O (format ya executable files katika macOS) hutumika kutangaza variables ambazo ni maalum kwa **kila thread** katika application yenye threads nyingi. Hii huhakikisha kwamba kila thread ina instance yake tofauti ya variable, na hivyo kutoa njia ya kuepuka migongano na kudumisha uadilifu wa data bila kuhitaji synchronization mechanisms za wazi kama mutexes.

Katika C na lugha zinazohusiana, unaweza kutangaza thread-local variable kwa kutumia keyword **`__thread`**. Hivi ndivyo inavyofanya kazi katika mfano wako:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Kipande hiki kinafafanua `tlv_var` kama kigezo cha thread-local. Kila thread inayoendesha msimbo huu itakuwa na `tlv_var` yake, na mabadiliko yanayofanywa na thread moja kwenye `tlv_var` hayataathiri `tlv_var` ya thread nyingine.

Katika binary ya Mach-O, data inayohusiana na vigezo vya thread-local hupangwa katika sehemu maalum:

- **`__DATA.__thread_vars`**: Sehemu hii ina metadata kuhusu vigezo vya thread-local, kama vile aina zake na hali yake ya uanzishaji.
- **`__DATA.__thread_bss`**: Sehemu hii hutumiwa kwa vigezo vya thread-local ambavyo havijaanzishwa waziwazi. Ni sehemu ya kumbukumbu iliyotengwa kwa data inayoanzishwa kwa thamani sifuri.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ya kudhibiti vigezo vya thread-local thread inapoisha. API hii hukuwezesha **kusajili destructors**—kazi maalum zinazofuta data ya thread-local thread inapokoma.

### Vipaumbele vya Thread

Kuelewa vipaumbele vya thread kunahusisha kuchunguza jinsi mfumo wa uendeshaji unavyoamua ni thread zipi zitaendeshwa na lini. Uamuzi huu huathiriwa na kiwango cha kipaumbele kilichowekwa kwa kila thread. Katika macOS na mifumo inayofanana na Unix, hili hushughulikiwa kwa kutumia dhana kama `nice`, `renice`, na madarasa ya Quality of Service (QoS).

#### Nice na Renice

1. **Nice:**
   - Thamani ya `nice` ya process ni nambari inayoathiri kipaumbele chake. Kila process ina thamani ya nice kuanzia -20 (kipaumbele cha juu zaidi) hadi 19 (kipaumbele cha chini zaidi). Thamani chaguomsingi ya nice process inapoundwa huwa 0 kwa kawaida.
   - Thamani ndogo ya nice (iliyo karibu zaidi na -20) huifanya process iwe ya kujitanguliza zaidi, na kuipa muda mwingi zaidi wa CPU ikilinganishwa na process nyingine zenye thamani kubwa zaidi za nice.
2. **Renice:**
   - `renice` ni amri inayotumika kubadilisha thamani ya nice ya process ambayo tayari inaendeshwa. Inaweza kutumika kurekebisha kipaumbele cha process moja kwa moja, kwa kuongeza au kupunguza mgao wake wa muda wa CPU kulingana na thamani mpya za nice.
   - Kwa mfano, ikiwa process inahitaji rasilimali zaidi za CPU kwa muda, unaweza kupunguza thamani yake ya nice kwa kutumia `renice`.

#### Madarasa ya Quality of Service (QoS)

Madarasa ya QoS ni mbinu ya kisasa zaidi ya kushughulikia vipaumbele vya thread, hasa katika mifumo kama macOS inayotumia **Grand Central Dispatch (GCD)**. Madarasa ya QoS huwawezesha watengenezaji **kuainisha** kazi katika viwango tofauti kulingana na umuhimu au uharaka wake. macOS hudhibiti vipaumbele vya thread kiotomatiki kulingana na madarasa haya ya QoS:

1. **User Interactive:**
   - Darasa hili ni la kazi zinazoingiliana na mtumiaji kwa sasa au zinazohitaji matokeo ya haraka ili kutoa matumizi mazuri kwa mtumiaji. Kazi hizi hupewa kipaumbele cha juu zaidi ili kiolesura kiendelee kujibu haraka (kwa mfano, uhuishaji au kushughulikia matukio).
2. **User Initiated:**
   - Kazi zinazoanzishwa na mtumiaji na ambazo anatarajia matokeo ya haraka, kama kufungua hati au kubofya kitufe kinachohitaji hesabu. Kazi hizi zina kipaumbele cha juu, lakini chini ya User Interactive.
3. **Utility:**
   - Kazi hizi hudumu kwa muda mrefu na kwa kawaida huonyesha kiashiria cha maendeleo (kwa mfano, kupakua faili au kuingiza data). Kipaumbele chake ni cha chini kuliko cha kazi zilizoanzishwa na mtumiaji, na hazihitaji kukamilika mara moja.
4. **Background:**
   - Darasa hili ni la kazi zinazoendeshwa chinichini na hazionekani kwa mtumiaji. Kazi hizi zinaweza kuwa kama kuorodhesha, kusawazisha data au kutengeneza nakala rudufu. Zina kipaumbele cha chini zaidi na athari ndogo zaidi kwa utendaji wa mfumo.

Kwa kutumia madarasa ya QoS, watengenezaji hawahitaji kudhibiti nambari halisi za vipaumbele; badala yake huzingatia aina ya kazi, na mfumo huboresha rasilimali za CPU ipasavyo.

Zaidi ya hayo, kuna **sera tofauti za upangaji wa thread** zinazobainisha seti ya vigezo vya upangaji ambavyo scheduler itazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Linaweza kuwa muhimu katika mashambulizi ya race condition.

## Matumizi Mabaya ya Process katika macOS

macOS hutoa mbinu nyingi za **process kuingiliana, kuwasiliana na kushiriki data**. Ingawa mbinu hizi ni muhimu kwa utendaji wa kawaida wa mfumo, washambuliaji wanaweza kuzitumia vibaya kwa injection, utekelezaji wa msimbo au ufikiaji wa data.

### Library Injection

Library Injection ni mbinu ambayo mshambuliaji **hulazimisha process kupakia library hasidi**. Baada ya kuingizwa, library huendeshwa ndani ya muktadha wa process lengwa, na kumpa mshambuliaji ruhusa na ufikiaji sawa na wa process hiyo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking huhusisha **kukamata miito ya function** au ujumbe ndani ya msimbo wa programu. Kwa ku-hook functions, mshambuliaji anaweza **kubadilisha tabia** ya process, kuchunguza data nyeti, au hata kudhibiti mtiririko wa utekelezaji.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Ukurasa huu unaeleza metadata ya ARM64 unwind, vikwazo vya PAC vya arm64e, na minyororo ya miito ya kubuni.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Mawasiliano kati ya Process

Mawasiliano kati ya Process (IPC) yanarejelea mbinu tofauti ambazo process tofauti hutumia **kushiriki na kubadilishana data**. Ingawa IPC ni ya msingi kwa programu nyingi halali, inaweza pia kutumiwa vibaya kuvunja utengano wa process, kuvuja taarifa nyeti au kutekeleza vitendo visivyoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Programu za Electron zinazoendeshwa zikiwa na env variables maalum zinaweza kuwa katika hatari ya process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kutekeleza **man in the browser attack**, inayoweza kuiba vibonye vilivyobonyezwa, traffic na cookies, na kuingiza scripts kwenye kurasa...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Faili za NIB **hufafanua vipengele vya kiolesura cha mtumiaji (UI)** na mwingiliano wake ndani ya programu. Hata hivyo, zinaweza **kutekeleza amri zozote**, na **Gatekeeper haizuii** programu ambayo tayari imetekelezwa kutekelezwa tena ikiwa **faili ya NIB imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya programu zozote zitekeleze amri zozote:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana kuingiza chaguo za JVM kupitia **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, au **`JDK_JAVA_OPTIONS`** na kupakia Java agent au native agent kabla programu haijaanza.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** hupakia mapema JavaScript ya mshambuliaji kupitia `--require` (faili) au `--import data:text/javascript,…` (bila faili, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** hupakia module kwenye REPL inayoingiliana, na **`ELECTRON_RUN_AS_NODE`** huwasha tena yote haya kwenye binary za Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana kuingiza msimbo kwenye programu za .NET kupitia **`DOTNET_STARTUP_HOOKS`** kabla ya `Main`, au kutumia vibaya utendaji wa debugging wa .NET wakati masharti yake ya awali yametimizwa.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash isiyoingiliana husoma **`BASH_ENV`**; POSIX shells zinazoingiliana husoma **`ENV`**; zsh husoma **`$ZDOTDIR/.zshenv`**; na fish husoma usanidi ulio chini ya **`XDG_CONFIG_HOME`** au **`XDG_DATA_DIRS`**. Kila moja inaweza kutekeleza faili ya startup inayodhibitiwa kabla ya amri iliyokusudiwa. Bash pia huendesha command substitution iliyowekwa kwenye **`PS4`** kila xtrace inapowashwa (kwa mfano, kupitia **`SHELLOPTS=xtrace`** iliyorithiwa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Kuanzisha `/bin/zsh -s` huifanya shell isome programu kutoka standard input. Kwa hiyo, downloader inayonakili hati iliyopangwa isiyoaminika kwenye stdin ya child bila kwanza kuichanganua hugeuza hati nzima kuwa chanzo cha shell. Loader moja iliyozingatiwa ilipitisha faili ya iCalendar ya umma kupitia anonymous pipe, mstari baada ya mstari. Metadata ya kalenda ilishindwa kutekelezwa kama amri, lakini zsh iliendelea hadi ilipofikia mistari inayoweza kutekelezwa iliyowekwa baada ya `DESCRIPTION:`. Mistari hiyo ilipakua na kuwasha application bundle iliyofuata. Aina ya maudhui iliyotarajiwa ya faili hiyo na hosting inayoaminika havikufanya hili kuwa salama; mpaka hatari ulikuwa kupitisha bytes zake kwa interpreter.<sup>[[5]](#references)</sup>

Hatua zinazohusiana zimeelezwa katika [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), na [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** au **`PHP_INI_SCAN_DIR`** zinaweza kupakia usanidi wa PHP unaodhibitiwa, ambao **`auto_prepend_file`** yake hutekelezwa kabla ya script lengwa.

[Usanidi wa PHP na injection ya startup ya `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Lua interpreter ya kujitegemea hutekeleza msimbo au `@file` kutoka **`LUA_INIT`** (au toleo lake mahususi) kabla ya kuchakata script lengwa.

[Injection ya startup ya Lua `LUA_INIT` (faili na msimbo wa ndani)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** na **`R_PROFILE`** huelekeza kwenye startup profiles zenye msimbo wa R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** pamoja na njia ya library ya R zinaweza badala yake kupakia kiotomatiki package iliyosakinishwa.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** huelekeza kwenye depot ambayo `config/startup.jl` yake hutekelezwa kiotomatiki.

[Injection kupitia `JULIA_DEPOT_PATH` na `startup.jl` ya Julia](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`**, au **`ERL_ZFLAGS`** zinaweza kuingiza expression ya Erlang VM **`-eval`** bila kuhitaji faili ya payload; workloads za Elixir mara nyingi huanzisha VM hiyohiyo.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** na **`OCTAVE_VERSION_INITFILE`** huelekeza kwenye startup scripts za Octave.

[Injection ya startup-file ya GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` ni programu ya .NET inayofanya kazi kwenye majukwaa mbalimbali, kwa hiyo environment variables kadhaa zinaweza kusababisha utekelezaji kabla ya amri: **`XDG_CONFIG_HOME`** huelekeza kwenye profile scripts zinazoendeshwa wakati wa startup, **`PSModulePath`** huteka udhibiti wa upakiaji otomatiki wa module (faili ya `.psm1` iliyowekwa kimakusudi huendeshwa wakati wa import na inaweza kufunika cmdlets zilizojengewa ndani), na variables za .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** na **`DOTNET_STARTUP_HOOKS`** hupakia msimbo wa mshambuliaji kwenye process kabla ya `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Angalia chaguo mbalimbali za kufanya script ya Perl itekeleze msimbo wowote katika:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Inawezekana pia kutumia vibaya env variables za ruby (**`RUBYOPT`**, **`RUBYLIB`**) ili kufanya scripts zozote zitekeleze msimbo wowote:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Mlolongo wa **`PYTHONWARNINGS`** na **`BROWSER`** wa standard library unaweza kutekeleza amri wakati wa kuchanganua warning-filter. Njia mbadala inayotumia faili huweka `sitecustomize.py` kwenye **`PYTHONPATH`**, ili uanzishaji wa kawaida wa `site` ui-import kabla ya script lengwa. **`PYTHONBREAKPOINT`** huendesha callable/module iliyochaguliwa msimbo unapofikia `breakpoint()`. Variables zinazotumika katika hali ya mwingiliano pekee, kama **`PYTHONSTARTUP`**, zina matumizi finyu zaidi.

Kumbuka kuwa executable zilizokusanywa kwa **`pyinstaller`** hazitumii environment variables hizi, hata kama zinaendeshwa kwa kutumia Python iliyopachikwa.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (na mbadala wake `EXINIT`) hutekelezwa kama Ex commands wakati wa startup ya kawaida, kwa hiyo `:!cmd` / `:call system(...)` husababisha utekelezaji wa msimbo mwathiriwa anapofungua Vim/Neovim ikiwa na mazingira yanayodhibitiwa:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Tofauti na hilo, Homebrew mara nyingi husakinisha Python chini ya `/opt/homebrew`, ambako wanachama wa kundi la `admin` la ndani wanaweza kuwa na uwezo wa kubadilisha launcher. Huku ni kuteka udhibiti wa binary inayoweza kuandikwa, si injection kupitia environment variable; hakiki umiliki na ACL kabla ya kuchukulia kuwa kuna uwezekano wa kuitumia vibaya.


## Ugunduzi

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni programu ya chanzo huria inayotumia **EndpointSecurity** kugundua na kuzuia process injection. Ni rejeleo zuri la kuelewa ishara zinazoweza kuonekana kupitia Endpoint Security, kwa kuwa hutoa tahadhari kuhusu:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** wakati wa process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- Miito ya **`task_for_pid`** — process moja ikiomba task port ya nyingine; hili ndilo sharti la awali la kuiingizia msimbo.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, ambazo huanzisha programu ya Electron katika hali ya debugging na kuruhusu mtu yeyote kuiunganisha na kuendesha msimbo ndani yake.<sup>[[3]](#references)</sup>
- **Kuunda symlink/hardlink kati ya viwango tofauti vya ruhusa** — mbinu ya kawaida ya "weka link kama mtumiaji wa kawaida, kisha ielekeze kwenye eneo lenye ruhusa za juu". Kumbuka kuwa **symlink zinaweza kugunduliwa lakini haziwezi kuzuiwa**: EndpointSecurity haionyeshi mahali link inapoelekezwa kabla haijaundwa.

### Miito inayofanywa na process nyingine

Katika [**chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kuona jinsi inavyowezekana kutumia function **`task_name_for_pid`** kupata taarifa kuhusu **process nyingine zinazoingiza msimbo kwenye process**, kisha kupata taarifa kuhusu process hizo nyingine.<sup>[[4]](#references)</sup>

Kumbuka kuwa ili kuita function hiyo, lazima uwe na **uid sawa** na ile inayoendesha process au uwe **root** (na hurejesha taarifa kuhusu process, si njia ya kuingiza msimbo).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — ugunduzi wa process injection katika macOS wa chanzo huria (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — mfumo wa EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Kwa nini programu za Electron haziwezi kuhifadhi siri zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Kugundua marekebisho ya task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Toleo jipya la MacSync macOS stealer linalenga wapenda crypto na watengenezaji](https://securelist.com/macsync-new-version/121383/)
