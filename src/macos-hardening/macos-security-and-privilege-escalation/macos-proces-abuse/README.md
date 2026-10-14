# Misbruik van macOS-prosesse

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

'n Proses is 'n instansie van 'n uitvoerbare lêer wat loop. Prosesse voer egter nie kode uit nie; drade doen. Daarom is **prosesse bloot houers vir drade wat loop** en verskaf hulle geheue, beskrywers, poorte, toestemmings...

Tradisioneel is prosesse binne ander prosesse (behalwe PID 1) begin deur **`fork`** aan te roep, wat 'n presiese kopie van die huidige proses skep. Daarna roep die **kindproses** gewoonlik **`execve`** aan om die nuwe uitvoerbare lêer te laai en dit uit te voer. Toe is **`vfork`** bekendgestel om hierdie proses te versnel sonder om geheue te kopieer.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een oproep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ID's terug na werklike ID's
- `POSIX_SPAWN_SETPGROUP`: Stel prosesgroeplidmaatskap in
- `POSUX_SPAWN_SETSIGDEF`: Stel die verstekgedrag vir seine in
- `POSIX_SPAWN_SETSIGMASK`: Stel die seinmasker in
- `POSIX_SPAWN_SETEXEC`: Voer uit in dieselfde proses (soos `execve`, met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano-allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasegmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Sluit alle lêerbeskrywings by verstek met exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-verskuiwing

Daarbenewens aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die voortgebringde proses beheer, en **`posix_spawn_file_actions`**-inskrywings wat lêerbeskrywings verander.

Wanneer 'n proses sterf, stuur dit die **terugkeerkode na die ouerproses** (as die ouerproses gesterf het, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouerproses moet hierdie waarde met `wait4()` of `waitid()` verkry. Totdat dit gebeur, bly die kindproses in 'n zombietoestand: dit word steeds gelys, maar gebruik nie hulpbronne nie.

### PID's

PID's (prosesidentifiseerders) identifiseer 'n unieke proses. In XNU is die **PID's** **64 bis** lank, neem hulle monotoon toe en **rol hulle nooit oor nie** (om misbruik te voorkom).

### Prosesgroepe, sessies en koalisies

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in 'n dopskrip sal byvoorbeeld in dieselfde prosesgroep wees, sodat dit moontlik is om **seine gelyktydig aan hulle te stuur**, byvoorbeeld met `kill`.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer 'n proses 'n sessie begin (`setsid(2)`), word die kinderprosesse binne die sessie geplaas, tensy hulle hul eie sessie begin.

'n Koalisie is nog 'n manier om prosesse in Darwin te groepeer. Wanneer 'n proses by 'n koalisie aansluit, kan dit toegang tot poelhulpbronne kry, 'n grootboek deel of deur Jetsam geteiken word. Koalisies het verskillende rolle: Leader, XPC service, Extension.

### Geloofsbriewe en personae

Elke proses het **geloofsbriewe** wat sy **voorregte in die stelsel identifiseer**. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander as die binêre lêer die `setuid/setgid`-bis het.\
Daar is verskeie funksies om **nuwe uid's/gid's in te stel**.

Die stelseloproep **`persona`** verskaf 'n **alternatiewe** stel **geloofsbriewe**. Deur 'n persona aan te neem, word die uid, gid en groeplidmaatskappe daarvan **gelyktydig** aangeneem. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) kan die struct gevind word:

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

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX-drade (`pthreads`), wat deel is van 'n standaard-API vir threading in C/C++. Die implementering van pthreads in macOS is in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie biblioteek verskaf die nodige funksies om drade te skep en te bestuur.
2. **Drade skep:** Die `pthread_create()`-funksie word gebruik om nuwe drade te skep. Intern roep hierdie funksie `bsdthread_create()` aan, 'n laervlak-stelseloproep wat spesifiek vir die XNU-kern (die kern waarop macOS gebaseer is) is. Hierdie stelseloproep neem verskeie vlae wat van `pthread_attr` (eienskappe) afgelei is en wat draadgedrag spesifiseer, insluitend skeduleringsbeleide en stapelgrootte.
   - **Verstekstapelgrootte:** Die verstekstapelgrootte vir nuwe drade is 512 KB, wat voldoende is vir tipiese bewerkings, maar via draadeienskappe aangepas kan word as meer of minder ruimte nodig is.
3. **Draadinitialisering:** Die `__pthread_init()`-funksie is noodsaaklik tydens draadopstelling en gebruik die `env[]`-argument om omgewingsveranderlikes te ontleed wat besonderhede oor die ligging en grootte van die stapel kan insluit.

#### Draadbeëindiging in macOS

1. **Drade verlaat:** Drade word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat 'n draad netjies afsluit, die nodige skoonmaakwerk uitvoer en 'n terugkeerwaarde aan enige joiners terugstuur.
2. **Draadskoonmaak:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` aangeroep om alle geassosieerde draadstrukture te verwyder. Dit deallokeer Mach-draadpoorte (Mach is die kommunikasiesubstelsel in die XNU-kern) en roep `bsdthread_terminate` aan, 'n stelseloproep wat die kernvlakstrukture verwyder wat met die draad geassosieer word.

#### Sinchronisasiemeganismes

Om toegang tot gedeelde hulpbronne te bestuur en wedlooptoestande te voorkom, verskaf macOS verskeie sinchronisasieprimitiewe. Dit is noodsaaklik in multithreading-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
   - **Gewone mutex (handtekening: 0x4D555458):** Standaardmutex met 'n geheuevoetspoor van 60 grepe (56 grepe vir die mutex en 4 grepe vir die handtekening).
   - **Vinnige mutex (handtekening: 0x4d55545A):** Soortgelyk aan 'n gewone mutex, maar geoptimaliseer vir vinniger bewerkings; dit is ook 60 grepe groot.
2. **Voorwaardeveranderlikes:**
   - Word gebruik om vir sekere toestande te wag en is 44 grepe groot (40 grepe plus 'n handtekening van 4 grepe).
   - **Voorwaardeveranderlike-eienskappe (handtekening: 0x434e4441):** Konfigurasie-eienskappe vir voorwaardeveranderlikes, 12 grepe groot.
3. **Eenmalige veranderlike (handtekening: 0x4f4e4345):**
   - Verseker dat 'n stuk initialiseringskode slegs een keer uitgevoer word. Dit is 12 grepe groot.
4. **Lees-skryf-slotte:**
   - Laat verskeie lesers of een skrywer op 'n slag toe en maak doeltreffende toegang tot gedeelde data moontlik.
   - **Lees-skryf-slot (handtekening: 0x52574c4b):** 196 grepe groot.
   - **Lees-skryf-slot-eienskappe (handtekening: 0x52574c41):** Eienskappe vir lees-skryf-slotte, 20 grepe groot.

> [!TIP]
> Die laaste 4 grepe van hierdie objekte word gebruik om oorlope op te spoor.

### Draadplaaslike veranderlikes (TLV)

**Draadplaaslike veranderlikes (TLV)** word in Mach-O-lêers (die formaat vir uitvoerbare lêers in macOS) gebruik om veranderlikes te verklaar wat **spesifiek vir elke draad** in 'n multithreaded-toepassing is. Dit verseker dat elke draad sy eie afsonderlike instansie van 'n veranderlike het, wat 'n manier bied om konflik te voorkom en data-integriteit te handhaaf sonder eksplisiete sinchronisasiemeganismes soos mutexes.

In C en verwante tale kan jy 'n draadplaaslike veranderlike met die sleutelwoord **`__thread`** verklaar. Só werk dit in jou voorbeeld:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Hierdie kodegreep definieer `tlv_var` as ’n thread-local variable. Elke thread wat hierdie kode uitvoer, het sy eie `tlv_var`, en veranderinge wat een thread aan `tlv_var` maak, beïnvloed nie `tlv_var` in ’n ander thread nie.

In die Mach-O-binêre lêer word data wat met thread-local variables verband hou, in spesifieke afdelings georganiseer:

- **`__DATA.__thread_vars`**: Hierdie afdeling bevat metadata oor die thread-local variables, soos hul tipes en initialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie afdeling word gebruik vir thread-local variables wat nie eksplisiet geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir nul-geïnisialiseerde data opsy gesit is.

Mach-O verskaf ook ’n spesifieke API, **`tlv_atexit`**, om thread-local variables te bestuur wanneer ’n thread eindig. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local data opruim wanneer ’n thread beëindig word.

### Threading-prioriteite

Om thread-prioriteite te verstaan, moet jy kyk na hoe die bedryfstelsel besluit watter threads uitgevoer word en wanneer. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke thread toegeken is. In macOS en Unix-agtige stelsels word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS)-klasse.

#### Nice en Renice

1. **Nice:**
   - Die `nice`-waarde van ’n proses is ’n getal wat sy prioriteit beïnvloed. Elke proses het ’n nice-waarde wat wissel van -20 (die hoogste prioriteit) tot 19 (die laagste prioriteit). Die verstekwaarde vir nice wanneer ’n proses geskep word, is gewoonlik 0.
   - ’n Laer nice-waarde (nader aan -20) maak ’n proses meer “selfsugtig” deur dit meer CPU-tyd te gee as ander prosesse met hoër nice-waardes.
2. **Renice:**
   - `renice` is ’n opdrag waarmee die nice-waarde van ’n proses wat reeds loop, verander kan word. Dit kan gebruik word om die prioriteit van prosesse dinamies aan te pas en hul CPU-tydtoewysing te verhoog of te verlaag op grond van nuwe nice-waardes.
   - Byvoorbeeld, as ’n proses tydelik meer CPU-hulpbronne nodig het, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS)-klasse

QoS-klasse is ’n meer moderne benadering tot die hantering van thread-prioriteite, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS-klasse laat ontwikkelaars toe om werk volgens belangrikheid of dringendheid in verskillende vlakke te **kategoriseer**. macOS bestuur thread-prioritisering outomaties op grond van hierdie QoS-klasse:

1. **User Interactive:**
   - Hierdie klas is vir take wat tans met die gebruiker interaksie het of onmiddellike resultate vereis om ’n goeie gebruikerservaring te bied. Hierdie take kry die hoogste prioriteit sodat die koppelvlak reageer (bv. animasies of gebeurtenishantering).
2. **User Initiated:**
   - Take wat die gebruiker begin en waarvoor onmiddellike resultate verwag word, soos om ’n dokument oop te maak of ’n knoppie te klik wat berekeninge vereis. Hierdie take het ’n hoë prioriteit, maar laer as User Interactive.
3. **Utility:**
   - Hierdie take loop lank en wys gewoonlik ’n vorderingsaanwyser (bv. lêers aflaai of data invoer). Hulle het ’n laer prioriteit as take wat deur die gebruiker begin is en hoef nie onmiddellik klaar te wees nie.
4. **Background:**
   - Hierdie klas is vir take wat in die agtergrond loop en nie vir die gebruiker sigbaar is nie. Dit kan take soos indeksering, sinkronisering of rugsteun insluit. Hulle het die laagste prioriteit en minimale impak op stelselwerkverrigting.

Met QoS-klasse hoef ontwikkelaars nie die presiese prioriteitsgetalle te bestuur nie; hulle kan eerder op die aard van die taak fokus, waarna die stelsel die CPU-hulpbronne dienooreenkomstig optimaliseer.

Daar is ook verskillende **thread-skeduleringsbeleide** wat ’n stel skeduleringsparameters spesifiseer wat die skeduleerder in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race-condition-aanvalle.

## Misbruik van macOS-prosesse

macOS bied baie meganismes waardeur **prosesse met mekaar kan kommunikeer en data kan deel**. Hoewel hierdie meganismes noodsaaklik is vir normale stelselwerking, kan aanvallers dit misbruik vir injection, kode-uitvoering of datatoegang.

### Library Injection

Library Injection is ’n tegniek waarin ’n aanvaller **’n proses dwing om ’n kwaadwillige library te laai**. Sodra dit ingevoeg is, loop die library binne die teikenproses en gee dit die aanvaller dieselfde toestemmings en toegang as die proses.

{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking behels dat **funksie-oproepe** of boodskappe binne sagtewarekode onderskep word. Deur funksies te hook, kan ’n aanvaller **die gedrag** van ’n proses verander, sensitiewe data waarneem of selfs beheer oor die uitvoeringsvloei verkry.

{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Hierdie bladsy behandel ARM64-unwind-metadata, arm64e-PAC-beperkings en sintetiese oproepkettings.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waarmee afsonderlike prosesse **data deel en uitruil**. Hoewel IPC noodsaaklik is vir baie wettige toepassings, kan dit ook misbruik word om proses-isolasie te ondermyn, sensitiewe inligting te lek of ongemagtigde aksies uit te voer.

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection in Electron-toepassings

Electron-toepassings wat met spesifieke omgewingsveranderlikes uitgevoer word, kan kwesbaar wees vir proses-injection:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die vlae `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser-aanval** uit te voer, wat dit moontlik maak om toetsaanslae, verkeer en koekies te steel en skripte in bladsye in te voeg...:

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-lêers **definieer gebruikerskoppelvlak- (UI-)elemente** en hul interaksies binne ’n toepassing. Hulle kan egter **willekeurige opdragte uitvoer**, en **Gatekeeper keer nie** dat ’n reeds uitgevoerde toepassing weer uitgevoer word as ’n **NIB-lêer gewysig is**. Daarom kan hulle gebruik word om willekeurige programme willekeurige opdragte te laat uitvoer:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection in Java-toepassings

Dit is moontlik om JVM-opsies deur **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** in te spuit en ’n Java- of native agent te laai voordat die toepassing begin.

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** laai aanvaller-JavaScript vooraf met `--require` (lêer) of `--import data:text/javascript,…` (sonder lêer, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** laai ’n module in ’n interaktiewe REPL, en **`ELECTRON_RUN_AS_NODE`** aktiveer dit alles weer op Electron-binêre lêers.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection in .Net-toepassings

Dit is moontlik om kode in .NET-toepassings in te spuit deur **`DOTNET_STARTUP_HOOKS`** voor `Main` te gebruik, of deur die .NET-ontfoutingsfunksionaliteit te misbruik wanneer die nodige voorvereistes teenwoordig is.

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nie-interaktiewe Bash lees **`BASH_ENV`**; interaktiewe POSIX-shells lees **`ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees konfigurasie onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n beheerde opstartlêer uitvoer voordat die bedoelde opdrag loop. Bash voer ook ’n command substitution uit wat in **`PS4`** geplaas is wanneer xtrace geaktiveer is (bv. deur oorgeërfde **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

As jy `/bin/zsh -s` begin, lees die shell ’n program vanaf standaardinvoer. Daarom verander ’n aflaaier wat ’n onbetroubare gestruktureerde dokument na die kindproses se stdin kopieer sonder om dit eers te ontleed, die hele dokument in shell-bronkode. Een waargenome loader het ’n openbare iCalendar-lêer reël vir reël deur ’n anonieme pyp gevoer. Kalender-metadata het as opdragte misluk, maar zsh het voortgegaan totdat dit uitvoerbare reëls ná `DESCRIPTION:` bereik het. Daardie reëls het die volgende toepassingsbondel afgelaai en begin. Die draer se verwagte inhoudtipe en vertroude hosting het dit nie veilig gemaak nie; die gevaarlike grens was om die grepe daarvan aan ’n interpreter deur te gee.<sup>[[5]](#references)</sup>

Verwante stadiums word behandel in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) en [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan beheerde PHP-konfigurasie laai waarvan **`auto_prepend_file`** uitgevoer word voordat die teikenskrip loop.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Die selfstandige Lua-interpreter voer kode of ’n `@file` vanaf **`LUA_INIT`** (of die weergawe-spesifieke variant daarvan) uit voordat die teikenskrip verwerk word.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** herlei na opstartprofiele wat R-kode bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** saam met ’n R-library-pad kan eerder ’n geïnstalleerde pakket outomaties laai.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** herlei na die depot waarvan `config/startup.jl` outomaties uitgevoer word.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang- en Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** of **`ERL_ZFLAGS`** kan ’n Erlang-VM-**`-eval`**-uitdrukking invoeg sonder dat ’n payload-lêer nodig is; Elixir-werkladings begin gewoonlik dieselfde VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** herlei na Octave-opstartscripte.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` is ’n kruisplatform-.NET-toepassing, daarom maak verskeie omgewingsveranderlikes uitvoering voor die opdrag moontlik: **`XDG_CONFIG_HOME`** herlei die profielskripte wat met opstart loop, **`PSModulePath`** kaap die outomatiese laai van modules (’n geplaasde `.psm1` loop tydens invoer en kan ingeboude cmdlets oorskadu), en die .NET-veranderlikes **`CORECLR_PROFILER`**/**`COR_PROFILER`** en **`DOTNET_STARTUP_HOOKS`** laai aanvallerkode in die proses voordat `Main` loop.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende opsies om ’n Perl-skrip willekeurige kode te laat uitvoer in:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om Ruby-omgewingsveranderlikes (**`RUBYOPT`**, **`RUBYLIB`**) te misbruik om willekeurige skripte willekeurige kode te laat uitvoer:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die standaardbiblioteekketting **`PYTHONWARNINGS`** en **`BROWSER`** kan ’n opdrag uitvoer terwyl waarskuwingsfilters ontleed word. ’n Alternatief wat ’n lêer gebruik, plaas `sitecustomize.py` op **`PYTHONPATH`**, sodat normale `site`-initialisering dit invoer voordat die teikenskrip loop. **`PYTHONBREAKPOINT`** voer ’n gekose callable/module uit wanneer die kode `breakpoint()` bereik. Veranderlikes wat net vir interaktiewe gebruik bedoel is, soos **`PYTHONSTARTUP`**, het ’n beperkter toepassingsgebied.

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes sal gebruik nie, selfs al loop hulle met ’n ingebedde Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (en sy `EXINIT`-terugvalopsie) word as Ex-opdragte uitgevoer tydens ’n normale opstart. Daarom lei `:!cmd` / `:call system(...)` tot kode-uitvoering wanneer ’n slagoffer Vim/Neovim met ’n beheerde omgewing oopmaak:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Afsonderlik installeer Homebrew dikwels Python onder `/opt/homebrew`, waar lede van die plaaslike `admin`-groep dalk die launcher kan vervang. Dit is ’n kaping van ’n skryfbare binêre lêer, nie injection deur ’n omgewingsveranderlike nie; verifieer eienaarskap en ACL’s voordat jy dit as uitbuitbaar beskou.

## Opsporing

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n oopbron-toepassing wat op **EndpointSecurity** gebaseer is en proses-injection opspoor en blokkeer. Dit is ’n goeie verwysing vir watter seine via Endpoint Security waarneembaar is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-omgewingsveranderlikes** tydens prosesuitvoering: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-oproepe — een proses wat ’n ander se task-port aanvra; dit is ’n voorvereiste om daarin te injecteer.
- **Electron-ontfoutingsargumente** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron-toepassing in ontfoutingsmodus begin en enigiemand toelaat om daaraan te koppel en kode daarin uit te voer.<sup>[[3]](#references)</sup>
- **Die skep van symlinks/hardlinks oor voorregvlakke heen** — die klassieke primitief: “plaas ’n skakel as ’n gewone gebruiker en laat dit na ’n bevoorregte ligging wys”. Let daarop dat **symlinks opgespoor maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die skakel se bestemming bloot voordat dit geskep word nie.

### Oproepe deur ander prosesse

In [**hierdie blogplasing**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy lees hoe die funksie **`task_name_for_pid`** gebruik kan word om inligting te verkry oor ander **prosesse wat kode in ’n proses injecteer**, en daarna inligting oor daardie ander proses te kry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** as die een wat die proses uitvoer of **root** moet wees om daardie funksie aan te roep (en dit gee inligting oor die proses terug, nie ’n manier om kode daarin te injecteer nie).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — oopbron-opsporing van macOS-proses-injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-raamwerk](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Waarom Electron-toepassings nie jou geheime vertroulik kan stoor nie: --inspect-opsie](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Opsporing van taakwysigings](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - ’n Nuwe weergawe van die MacSync macOS-stealer teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
