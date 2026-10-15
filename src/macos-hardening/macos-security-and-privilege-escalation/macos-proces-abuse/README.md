# macOS-prosesmisbruik

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

'n Proses is 'n instansie van 'n uitvoerbare lêer wat loop. Prosesse voer egter nie kode uit nie; drade doen dit. Daarom is **prosesse bloot houers vir drade wat loop** en voorsien hulle die geheue, beskrywings, poorte, toestemmings...

Tradisioneel is prosesse binne ander prosesse (behalwe PID 1) begin deur **`fork`** aan te roep, wat 'n presiese kopie van die huidige proses skep. Daarna roep die **kindproses** gewoonlik **`execve`** aan om die nuwe uitvoerbare lêer te laai en uit te voer. Toe is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder om geheue te kopieer.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een aanroep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ID's terug na werklike ID's
- `POSIX_SPAWN_SETPGROUP`: Stel die proses se groepstoewysing in
- `POSUX_SPAWN_SETSIGDEF`: Stel die verstekgedrag vir seine in
- `POSIX_SPAWN_SETSIGMASK`: Stel die seinmasker in
- `POSIX_SPAWN_SETEXEC`: Voer `exec` in dieselfde proses uit (soos `execve`, maar met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano-allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasegmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Maak by verstek alle lêerbeskrywings toe met exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-verskuiwing

Daarbenewens aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die geskepte proses beheer, en **`posix_spawn_file_actions`**-inskrywings wat lêerbeskrywings wysig.

Wanneer 'n proses sterf, stuur dit die **terugkeerkode na die ouerproses** (as die ouerproses gesterf het, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouerproses moet hierdie waarde verkry deur `wait4()` of `waitid()` aan te roep. Totdat dit gebeur, bly die kindproses in 'n zombie-toestand: dit word steeds gelys, maar gebruik geen hulpbronne nie.

### PID's

PID's, oftewel prosesidentifiseerders, identifiseer 'n unieke proses. In XNU is die **PID's** **64 bis** lank, neem hulle eentonig toe en **rol hulle nooit om nie** (om misbruik te voorkom).

### Prosesgroepe, sessies en Coalations

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Byvoorbeeld, opdragte in 'n dopskrip sal in dieselfde prosesgroep wees, sodat dit moontlik is om **hulle saam te sein**, byvoorbeeld deur `kill` te gebruik.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer 'n proses 'n sessie begin (`setsid(2)`), word die kindprosesse binne die sessie geplaas, tensy hulle hul eie sessie begin.

Coalition is nog 'n manier om prosesse in Darwin te groepeer. Wanneer 'n proses by 'n coalation aansluit, kan dit toegang tot hulpbronpoele kry, 'n ledger deel of deur Jetsam geraak word. Coalations het verskillende rolle: Leader, XPC service, Extension.

### Geloofsbriewe en Personae

Elke proses bevat **geloofsbriewe** wat sy **voorregte** in die stelsel **identifiseer**. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander as die binêre lêer die `setuid/setgid`-bis het.\
Daar is verskeie funksies om **nuwe uids/gids in te stel**.

Die stelseloproep **`persona`** verskaf 'n **alternatiewe** stel **geloofsbriewe**. Deur 'n persona aan te neem, neem die proses terselfdertyd die persona se uid, gid en groeplidmaatskappe aan. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) kan die struct gevind word:

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

## Basiese inligting oor drade

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX-drade (`pthreads`), wat deel is van ’n standaard-API vir drade in C/C++. Die implementering van pthreads in macOS is in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie biblioteek verskaf die nodige funksies om drade te skep en te bestuur.
2. **Drade skep:** Die funksie `pthread_create()` word gebruik om nuwe drade te skep. Intern roep hierdie funksie `bsdthread_create()` aan, ’n laervlak-stelseloproep wat spesifiek vir die XNU-kern is (die kern waarop macOS gebaseer is). Hierdie stelseloproep neem verskeie vlae aan wat van `pthread_attr` (eienskappe) afgelei word en die gedrag van die draad spesifiseer, insluitend skeduleringsbeleide en stapelgrootte.
   - **Verstekstapelgrootte:** Die verstekstapelgrootte vir nuwe drade is 512 KB. Dit is voldoende vir tipiese bewerkings, maar kan met draadeienskappe aangepas word as meer of minder ruimte nodig is.
3. **Draadinisialisering:** Die funksie `__pthread_init()` is noodsaaklik tydens die opstelling van ’n draad. Dit gebruik die argument `env[]` om omgewingsveranderlikes te ontleed, wat besonderhede oor die stapel se ligging en grootte kan bevat.

#### Beëindiging van drade in macOS

1. **Drade verlaat:** Drade word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n draad toe om ordelik te eindig, die nodige opruiming uit te voer en ’n terugkeerwaarde aan enige drade wat daarop wag, terug te stuur.
2. **Draadopruiming:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` aangeroep. Dit hanteer die verwydering van alle gepaardgaande draadstrukture. Dit deallokeer Mach-draadpoorte (Mach is die kommunikasiestelsel in die XNU-kern) en roep `bsdthread_terminate` aan, ’n syscall wat die kernvlakstrukture verwyder wat met die draad geassosieer word.

#### Sinchronisasiemeganismes

Om toegang tot gedeelde hulpbronne te bestuur en rastoestande te vermy, verskaf macOS verskeie sinchronisasieprimitiewe. Dit is noodsaaklik in multithreading-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
   - **Gewone mutex (handtekening: 0x4D555458):** Standaardmutex met ’n geheuevoetspoor van 60 grepe (56 grepe vir die mutex en 4 grepe vir die handtekening).
   - **Vinnige mutex (handtekening: 0x4d55545A):** Soortgelyk aan ’n gewone mutex, maar geoptimaliseer vir vinniger bewerkings; ook 60 grepe groot.
2. **Toestandsveranderlikes:**
   - Word gebruik om vir sekere toestande te wag; hulle is 44 grepe groot (40 grepe plus ’n handtekening van 4 grepe).
   - **Eienskappe van toestandsveranderlikes (handtekening: 0x434e4441):** Konfigurasie-eienskappe vir toestandsveranderlikes, 12 grepe groot.
3. **Eenmalige veranderlike (handtekening: 0x4f4e4345):**
   - Verseker dat ’n stuk inisialiseringskode net een keer uitgevoer word. Dit is 12 grepe groot.
4. **Lees-skryf-slotte:**
   - Laat verskeie lesers of een skrywer op ’n slag toe, wat doeltreffende toegang tot gedeelde data vergemaklik.
   - **Lees-skryf-slot (handtekening: 0x52574c4b):** 196 grepe groot.
   - **Eienskappe van lees-skryf-slotte (handtekening: 0x52574c41):** Eienskappe vir lees-skryf-slotte, 20 grepe groot.

> [!TIP]
> Die laaste 4 grepe van hierdie objekte word gebruik om overflows op te spoor.

### Draadplaaslike veranderlikes (TLV)

**Draadplaaslike veranderlikes (TLV)** word in Mach-O-lêers (die formaat vir uitvoerbare lêers in macOS) gebruik om veranderlikes te verklaar wat spesifiek vir **elke draad** in ’n multithread-toepassing is. Dit verseker dat elke draad sy eie afsonderlike instansie van ’n veranderlike het. Só kan konflikte vermy en data-integriteit behou word sonder dat eksplisiete sinchronisasiemeganismes soos mutexes nodig is.

In C en verwante tale kan jy ’n draadplaaslike veranderlike met die sleutelwoord **`__thread`** verklaar. Só werk dit in jou voorbeeld:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Hierdie brokkie definieer `tlv_var` as ’n thread-local veranderlike. Elke thread wat hierdie kode uitvoer, het sy eie `tlv_var`, en veranderinge wat een thread aan `tlv_var` maak, beïnvloed nie `tlv_var` in ’n ander thread nie.

In die Mach-O-binêre lêer word data oor thread-local veranderlikes in spesifieke afdelings georganiseer:

- **`__DATA.__thread_vars`**: Hierdie afdeling bevat metadata oor die thread-local veranderlikes, soos hul tipes en inisialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie afdeling word gebruik vir thread-local veranderlikes wat nie eksplisiet geïnisialiseer word nie. Dit is ’n deel van die geheue wat vir data gereserveer is wat met nulle geïnisialiseer word.

Mach-O bied ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local veranderlikes te bestuur wanneer ’n thread eindig. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local data opruim wanneer ’n thread beëindig word.

### Thread-prioriteite

Om thread-prioriteite te verstaan, moet jy kyk na hoe die bedryfstelsel besluit watter threads om te laat loop en wanneer. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke thread toegewys is. In macOS- en Unix-agtige stelsels word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS)-klasse.

#### Nice en Renice

1. **Nice:**
   - Die `nice`-waarde van ’n proses is ’n getal wat die prioriteit daarvan beïnvloed. Elke proses het ’n nice-waarde van -20 (die hoogste prioriteit) tot 19 (die laagste prioriteit). Die verstek-nice-waarde wanneer ’n proses geskep word, is gewoonlik 0.
   - ’n Laer nice-waarde (nader aan -20) maak ’n proses meer “selfsugtig” deur dit meer CPU-tyd te gee as ander prosesse met hoër nice-waardes.
2. **Renice:**
   - `renice` is ’n opdrag waarmee die nice-waarde van ’n proses wat reeds loop, verander kan word. Dit kan gebruik word om die prioriteit van prosesse dinamies aan te pas en hul CPU-tydtoewysing te verhoog of te verlaag op grond van nuwe nice-waardes.
   - As ’n proses byvoorbeeld tydelik meer CPU-hulpbronne benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS)-klasse

QoS-klasse is ’n meer moderne benadering tot die hantering van thread-prioriteite, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS-klasse laat ontwikkelaars toe om werk volgens die belangrikheid of dringendheid daarvan in verskillende vlakke te **kategoriseer**. macOS bestuur thread-prioritisering outomaties op grond van hierdie QoS-klasse:

1. **User Interactive:**
   - Hierdie klas is vir take wat tans met die gebruiker interaksie het of onmiddellike resultate vereis om ’n goeie gebruikerservaring te bied. Hierdie take kry die hoogste prioriteit om die koppelvlak responsief te hou (bv. animasies of gebeurtenishantering).
2. **User Initiated:**
   - Take wat die gebruiker begin en waarvoor onmiddellike resultate verwag word, soos om ’n dokument oop te maak of op ’n knoppie te klik wat berekeninge vereis. Hulle het ’n hoë prioriteit, maar is onder User Interactive.
3. **Utility:**
   - Hierdie take loop lank en wys gewoonlik ’n vorderingsaanwyser (bv. lêers aflaai of data invoer). Hulle het ’n laer prioriteit as take wat deur die gebruiker begin is, en hoef nie onmiddellik klaar te wees nie.
4. **Background:**
   - Hierdie klas is vir take wat in die agtergrond werk en nie vir die gebruiker sigbaar is nie. Dit kan take soos indeksering, sinkronisering of rugsteun insluit. Hulle het die laagste prioriteit en minimale impak op stelselwerkverrigting.

Met QoS-klasse hoef ontwikkelaars nie die presiese prioriteitsgetalle te bestuur nie; hulle fokus eerder op die aard van die taak, en die stelsel optimaliseer die CPU-hulpbronne dienooreenkomstig.

Daar is ook verskillende **thread-skeduleringsbeleide** wat ’n stel skeduleringsparameters spesifiseer wat die skeduleerder in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition-aanvalle.

## macOS-prosesmisbruik

macOS bied baie meganismes waarmee **prosesse kan interaksie hê, kommunikeer en data deel**. Hoewel hierdie meganismes noodsaaklik is vir die normale werking van die stelsel, kan aanvallers hulle misbruik vir injection, kode-uitvoering of datatoegang.

### Library Injection

Library Injection is ’n tegniek waarin ’n aanvaller **’n proses dwing om ’n kwaadwillige library te laai**. Sodra dit ingespuit is, loop die library in die konteks van die teikenproses en gee dit die aanvaller dieselfde toestemmings en toegang as die proses.

{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking behels dat **funksie-oproepe** of boodskappe binne sagtewarekode **onderskep** word. Deur funksies te hook, kan ’n aanvaller **die gedrag van ’n proses verander**, sensitiewe data waarneem of selfs beheer oor die uitvoeringsvloei verkry.

{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Hierdie bladsy dek ARM64-unwind-metadata, arm64e-PAC-beperkings en sintetiese oproepkettings.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waarmee afsonderlike prosesse **data deel en uitruil**. Hoewel IPC fundamenteel is vir baie wettige toepassings, kan dit ook misbruik word om proses-isolasie te ondermyn, sensitiewe inligting te lek of ongemagtigde aksies uit te voer.

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-toepassings wat met spesifieke omgewingsveranderlikes uitgevoer word, kan kwesbaar wees vir process injection:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die vlae `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser-aanval** uit te voer waarmee sleutelaanslae, verkeer en koekies gesteel kan word, en skrifte in bladsye ingespuit kan word...:

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-lêers **definieer gebruikerskoppelvlak- (UI-)elemente** en hul interaksies binne ’n toepassing. Hulle kan egter **willekeurige opdragte uitvoer**, en **Gatekeeper keer nie dat** ’n reeds uitgevoerde toepassing weer uitgevoer word as ’n **NIB-lêer gewysig is nie**. Daarom kan hulle gebruik word om willekeurige programme willekeurige opdragte te laat uitvoer:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om JVM-opsies via **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** in te spuit en ’n Java- of native agent te laai voordat die toepassing begin.

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** laai aanvaller-JavaScript vooraf via `--require` (lêer) of `--import data:text/javascript,…` (sonder lêer, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** laai ’n module in ’n interaktiewe REPL, en **`ELECTRON_RUN_AS_NODE`** aktiveer dit alles weer op Electron-binêre lêers.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om kode in .NET-toepassings in te spuit via **`DOTNET_STARTUP_HOOKS`** voordat `Main` begin, of deur die .NET-debugfunksionaliteit te misbruik wanneer die nodige voorvereistes teenwoordig is.

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nie-interaktiewe Bash lees **`BASH_ENV`**; interaktiewe POSIX-shells lees **`ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees konfigurasie onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n beheerde opstartlêer uitvoer voordat die bedoelde opdrag loop. Bash voer ook ’n opdragvervanging uit wat in **`PS4`** geplaas is wanneer xtrace geaktiveer is (bv. via oorgeërfde **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Wanneer `/bin/zsh -s` begin word, lees die shell ’n program vanaf standaardinvoer. Daarom verander ’n aflaaier wat ’n onbetroubare gestruktureerde dokument na die kindproses se stdin kopieer sonder om dit eers te ontleed, die hele dokument in shell-bronkode. Een waargenome loader het ’n publieke iCalendar-lêer reël vir reël deur ’n anonieme pyp gevoer. Kalender-metadata het as opdragte misluk, maar zsh het aangehou totdat dit uitvoerbare reëls bereik het wat ná `DESCRIPTION:` geplaas is. Daardie reëls het die volgende toepassingbundel afgelaai en begin. Die draer se verwagte inhoudstipe en betroubare gasheer het dit nie veilig gemaak nie; die gevaarlike grens was om die grepe daarvan aan ’n interpreter deur te gee.<sup>[[5]](#references)</sup>

Verwante stadiums word gedek in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) en [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan beheerde PHP-konfigurasie laai waarvan **`auto_prepend_file`** uitgevoer word voordat die teikenskrip loop.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Die selfstandige Lua-interpreter voer kode of ’n `@file` vanaf **`LUA_INIT`** (of sy weergawespesifieke variant) uit voordat die teikenskrip verwerk word.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** herlei na opstartprofiele wat R-kode bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** plus ’n R-library-pad kan eerder ’n geïnstalleerde pakket outomaties laai.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** herlei na die depot waarvan `config/startup.jl` outomaties uitgevoer word.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** of **`ERL_ZFLAGS`** kan ’n Erlang VM **`-eval`**-uitdrukking inspuit sonder dat ’n payload-lêer nodig is; Elixir-werkladings begin gewoonlik dieselfde VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** herlei na Octave-opstarts skrifte.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` is ’n kruisplatform-.NET-toepassing, daarom maak verskeie omgewingsveranderlikes uitvoering voor die opdrag moontlik: **`XDG_CONFIG_HOME`** herlei die profielskrifte wat tydens opstart loop, **`PSModulePath`** kaap outomatiese modulelaai (’n geplante `.psm1` loop tydens invoer en kan ingeboude cmdlets oorskadu), en die .NET-veranderlikes **`CORECLR_PROFILER`**/**`COR_PROFILER`** en **`DOTNET_STARTUP_HOOKS`** laai aanvallerkode in die proses voordat `Main` begin.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende opsies om ’n Perl-skrip willekeurige kode te laat uitvoer in:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om Ruby-omgewingsveranderlikes (**`RUBYOPT`**, **`RUBYLIB`**) te misbruik om willekeurige skrifte willekeurige kode te laat uitvoer:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die **`PYTHONWARNINGS`**- en **`BROWSER`**-standaardbiblioteekketting kan ’n opdrag uitvoer tydens die ontleding van waarskuwingsfilters. ’n Alternatief wat ’n lêer gebruik, plaas `sitecustomize.py` op **`PYTHONPATH`** sodat normale `site`-inisialisering dit invoer voordat die teikenskrip loop. **`PYTHONBREAKPOINT`** voer ’n gekose callable/module uit wanneer die kode `breakpoint()` bereik. Omgewingsveranderlikes wat slegs interaktief werk, soos **`PYTHONSTARTUP`**, het ’n beperkter toepaslikheid.

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes sal gebruik nie, selfs al loop hulle met ingebedde Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (en sy `EXINIT`-terugvalopsie) word tydens ’n normale opstart as Ex-opdragte uitgevoer. Daarom kan `:!cmd` / `:call system(...)` kode-uitvoering veroorsaak wanneer ’n slagoffer Vim/Neovim met ’n beheerde omgewing oopmaak:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Afsonderlik installeer Homebrew dikwels Python onder `/opt/homebrew`, waar lede van die plaaslike `admin`-groep moontlik die lanseerder kan vervang. Dit is ’n kaping van ’n skryfbare binêre lêer, eerder as injection via ’n omgewingsveranderlike; kontroleer eienaarskap en ACL’s voordat jy dit as uitbuitbaar beskou.


## Opsporing

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n oopbron-toepassing wat op **EndpointSecurity** gebaseer is en process injection opspoor en blokkeer. Dit is ’n goeie verwysing vir die seine wat via Endpoint Security waarneembaar is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-omgewingsveranderlikes** tydens prosesuitvoering: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-oproepe — een proses wat vir ’n ander proses se taakpoort vra; dit is ’n voorvereiste om kode daarin in te spuit.
- **Electron-debugargumente** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron-toepassing in debugmodus begin en enigiemand toelaat om daaraan te koppel en kode daarin uit te voer.<sup>[[3]](#references)</sup>
- **Skep van simskakels/hardskakels oor voorregvlakke heen** — die klassieke primitief: “plaas ’n skakel as ’n gewone gebruiker en wys dit na ’n bevoorregte ligging”. Let daarop dat **simskakels opgespoor kan word, maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die skakelbestemming voor skepping bloot nie.

### Oproepe deur ander prosesse

In [**hierdie blogplasing**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy lees hoe die funksie **`task_name_for_pid`** gebruik kan word om inligting te kry oor ander **prosesse wat kode in ’n proses inspuit**, en daarna inligting oor daardie ander proses te verkry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** moet hê as die een waaronder die proses loop, of **root** moet wees, om daardie funksie aan te roep (en dit gee inligting oor die proses terug, nie ’n manier om kode in te spuit nie).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — oopbron-opsporing van macOS-process injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-raamwerk](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Waarom Electron-toepassings nie jou geheime vertroulik kan stoor nie: die --inspect-opsie](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Opsporing van taakwysigings](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - ’n Nuwe weergawe van die MacSync macOS-dief teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
