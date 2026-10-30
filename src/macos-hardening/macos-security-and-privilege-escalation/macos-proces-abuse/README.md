# macOS-prosesmisbruik

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

’n Proses is ’n instansie van ’n uitvoerbare program wat loop, maar prosesse voer nie kode uit nie; threads doen dit. Daarom is **prosesse bloot houers vir threads wat loop** en verskaf hulle geheue, beskrywings, poorte, toestemmings...

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat ’n presiese kopie van die huidige proses skep. Die **kindproses** sou dan gewoonlik **`execve`** aanroep om die nuwe uitvoerbare program te laai en dit te laat loop. Daarna is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder om geheue te kopieer.\
Toe is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een aanroep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ID's terug na die werklike ID's
- `POSIX_SPAWN_SETPGROUP`: Stel die proses se groepverbintenis in
- `POSUX_SPAWN_SETSIGDEF`: Stel die verstekgedrag vir seine in
- `POSIX_SPAWN_SETSIGMASK`: Stel die seinmasker in
- `POSIX_SPAWN_SETEXEC`: Voer in dieselfde proses uit (soos `execve`, maar met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano-toewyser
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasegmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Maak alle lêerbeskrywings by verstek toe met exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-skuifwaarde

Verder aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die proses wat geskep word beheer, en **`posix_spawn_file_actions`**-inskrywings wat lêerbeskrywings wysig.

Wanneer ’n proses sterf, stuur dit die **terugkeerkode aan die ouerproses** (as die ouerproses gesterf het, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouer moet hierdie waarde kry deur `wait4()` of `waitid()` aan te roep. Totdat dit gebeur, bly die kind in ’n zombietoestand: dit word steeds gelys, maar gebruik geen hulpbronne nie.

### PIDs

PIDs, of prosesidentifiseerders, identifiseer ’n unieke proses. In XNU is **PIDs** **64-bis**, neem hulle monotoon toe en **loop hulle nooit oor nie** (om misbruik te voorkom).

### Prosesgroepe, sessies en koalisies

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in ’n shell script sal byvoorbeeld in dieselfde prosesgroep wees, sodat dit moontlik is om **seine gelyktydig aan hulle te stuur**, byvoorbeeld deur `kill` te gebruik.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer ’n proses ’n sessie begin (`setsid(2)`), word die kinderprosesse binne die sessie geplaas, tensy hulle hul eie sessie begin.

’n Koalisie is nog ’n manier om prosesse in Darwin te groepeer. Wanneer ’n proses by ’n koalisie aansluit, kan dit toegang tot ’n poel hulpbronne kry, ’n grootboek deel of deur Jetsam geteiken word. Koalisies het verskillende rolle: Leader, XPC service, Extension.

### Geloofsbriewe en personas

Elke proses hou **geloofsbriewe** wat **sy voorregte** in die stelsel **identifiseer**. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander as die binêre lêer die `setuid/setgid`-bis het.\
Daar is verskeie funksies om **nuwe uids/gids in te stel**.

Die stelseloproep **`persona`** verskaf ’n **alternatiewe** stel **geloofsbriewe**. Wanneer ’n persona aangeneem word, word sy uid, gid en groepk lidmaatskappe **gelyktydig** oorgeneem. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) kan die struktuur gevind word:

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

## Basiese inligting oor threads

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX-threads (`pthreads`), wat deel is van ’n standaard-API vir threading in C/C++. Die implementering van pthreads in macOS is in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie biblioteek verskaf die nodige funksies om threads te skep en te bestuur.
2. **Threads skep:** Die funksie `pthread_create()` word gebruik om nuwe threads te skep. Intern roep hierdie funksie `bsdthread_create()` aan, ’n laer-vlak-stelseloproep wat spesifiek is vir die XNU-kern (die kern waarop macOS gebaseer is). Hierdie stelseloproep neem verskeie vlae, afgelei van `pthread_attr` (eienskappe), wat thread-gedrag spesifiseer, insluitend skeduleringsbeleide en stapelgrootte.
   - **Verstekstapelgrootte:** Die verstekstapelgrootte vir nuwe threads is 512 KB. Dit is voldoende vir tipiese bewerkings, maar kan met thread-eienskappe aangepas word indien meer of minder spasie nodig is.
3. **Thread-inisialisering:** Die funksie `__pthread_init()` is noodsaaklik tydens thread-opstelling. Dit gebruik die argument `env[]` om omgewingsveranderlikes te ontleed wat besonderhede oor die stapel se ligging en grootte kan bevat.

#### Thread-beëindiging in macOS

1. **Threads verlaat:** Threads word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n thread toe om skoon te verlaat, die nodige opruiming uit te voer en ’n terugkeerwaarde aan enige threads wat daarop wag om aan te sluit, terug te stuur.
2. **Thread-opruiming:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` aangeroep. Dit hanteer die verwydering van alle gepaardgaande thread-strukture. Dit deallokeer Mach-thread-poorte (Mach is die kommunikasiesubstelsel in die XNU-kern) en roep `bsdthread_terminate` aan, ’n stelseloproep wat die kernvlakstrukture verwyder wat met die thread geassosieer word.

#### Sinchronisasiemeganismes

Om toegang tot gedeelde hulpbronne te bestuur en rastoestande te vermy, bied macOS verskeie sinchronisasieprimitiewe. Dit is noodsaaklik in multithreading-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
   - **Gewone mutex (handtekening: 0x4D555458):** Standaard-mutex met ’n geheuevoetspoor van 60 grepe (56 grepe vir die mutex en 4 grepe vir die handtekening).
   - **Fast mutex (handtekening: 0x4d55545A):** Soortgelyk aan ’n gewone mutex, maar geoptimaliseer vir vinniger bewerkings; ook 60 grepe groot.
2. **Voorwaardeveranderlikes:**
   - Word gebruik om vir sekere voorwaardes te wag; hulle is 44 grepe groot (40 grepe plus ’n handtekening van 4 grepe).
   - **Voorwaardeveranderlike-eienskappe (handtekening: 0x434e4441):** Opstellingseienskappe vir voorwaardeveranderlikes; 12 grepe groot.
3. **Once-veranderlike (handtekening: 0x4f4e4345):**
   - Verseker dat ’n stuk inisialiseringskode slegs een keer uitgevoer word. Dit is 12 grepe groot.
4. **Lees-skryf-slotte:**
   - Laat verskeie lesers of een skrywer op ’n slag toe, wat doeltreffende toegang tot gedeelde data moontlik maak.
   - **Lees-skryf-slot (handtekening: 0x52574c4b):** 196 grepe groot.
   - **Lees-skryf-slot-eienskappe (handtekening: 0x52574c41):** Eienskappe vir lees-skryf-slotte; 20 grepe groot.

> [!TIP]
> Die laaste 4 grepe van hierdie objekte word gebruik om oorlope op te spoor.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** word in Mach-O-lêers (die formaat vir uitvoerbare lêers in macOS) gebruik om veranderlikes te verklaar wat in ’n multithreaded toepassing spesifiek vir **elke thread** is. Dit verseker dat elke thread sy eie afsonderlike instansie van ’n veranderlike het. Só kan konflikte vermy en data-integriteit behou word sonder dat eksplisiete sinchronisasiemeganismes soos mutexes nodig is.

In C en verwante tale kan jy ’n thread-plaaslike veranderlike met die sleutelwoord **`__thread`** verklaar. Só werk dit in jou voorbeeld:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Hierdie snippet definieer `tlv_var` as ’n thread-local-veranderlike. Elke thread wat hierdie kode uitvoer, het sy eie `tlv_var`, en veranderinge wat een thread aan `tlv_var` maak, beïnvloed nie `tlv_var` in ’n ander thread nie.

In die Mach-O-binêre lêer word data wat met thread-local-veranderlikes verband hou, in spesifieke afdelings georganiseer:

- **`__DATA.__thread_vars`**: Hierdie afdeling bevat metadata oor die thread-local-veranderlikes, soos hul tipes en inisialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie afdeling word gebruik vir thread-local-veranderlikes wat nie uitdruklik geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir data gereserveer is wat met nulle geïnisialiseer word.

Mach-O bied ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local-veranderlikes te bestuur wanneer ’n thread eindig. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local-data opruim wanneer ’n thread beëindig word.

### Threadprioriteite

Om threadprioriteite te verstaan, moet jy kyk na hoe die bedryfstelsel besluit watter threads wanneer uitgevoer word. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke thread toegeken is. In macOS en Unix-agtige stelsels word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS)-klasse.

#### Nice en Renice

1. **Nice:**
   - Die `nice`-waarde van ’n proses is ’n getal wat die prioriteit daarvan beïnvloed. Elke proses het ’n nice-waarde wat van -20 (die hoogste prioriteit) tot 19 (die laagste prioriteit) strek. Die verstek-nice-waarde wanneer ’n proses geskep word, is gewoonlik 0.
   - ’n Laer nice-waarde (nader aan -20) maak ’n proses meer “selfsugtig”, wat dit meer SVE-tyd gee as ander prosesse met hoër nice-waardes.
2. **Renice:**
   - `renice` is ’n opdrag waarmee die nice-waarde van ’n proses wat reeds loop, verander kan word. Dit kan gebruik word om die prioriteit van prosesse dinamies aan te pas en hul SVE-tydtoekenning te verhoog of te verlaag op grond van nuwe nice-waardes.
   - As ’n proses byvoorbeeld tydelik meer SVE-hulpbronne benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS)-klasse

QoS-klasse is ’n moderner benadering tot die hantering van threadprioriteite, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS-klasse laat ontwikkelaars toe om werk volgens die belangrikheid of dringendheid daarvan in verskillende vlakke te **kategoriseer**. macOS bestuur threadprioritisering outomaties op grond van hierdie QoS-klasse:

1. **User Interactive:**
   - Hierdie klas is vir take wat op daardie oomblik met die gebruiker interaksie het, of onmiddellike resultate vereis om ’n goeie gebruikerservaring te bied. Hierdie take kry die hoogste prioriteit sodat die koppelvlak responsief bly (bv. animasies of gebeurtenishantering).
2. **User Initiated:**
   - Take wat die gebruiker begin en waarvoor onmiddellike resultate verwag word, soos om ’n dokument oop te maak of ’n knoppie te klik wat berekeninge vereis. Dit is hoëprioriteittake, maar is laer as User Interactive.
3. **Utility:**
   - Hierdie take loop lank en vertoon gewoonlik ’n vorderingsaanwyser (bv. die aflaai van lêers of invoer van data). Hulle het ’n laer prioriteit as take wat deur die gebruiker begin is, en hoef nie onmiddellik klaar te wees nie.
4. **Background:**
   - Hierdie klas is vir take wat in die agtergrond loop en nie vir die gebruiker sigbaar is nie. Dit kan take soos indeksering, sinkronisering of rugsteun insluit. Hulle het die laagste prioriteit en die minste invloed op stelselwerkverrigting.

Met QoS-klasse hoef ontwikkelaars nie die presiese prioriteitsgetalle te bestuur nie. Hulle fokus eerder op die aard van die taak, en die stelsel optimaliseer die SVE-hulpbronne dienooreenkomstig.

Daar is ook verskillende **thread-skeduleringsbeleide** wat ’n stel skeduleringsparameters spesifiseer wat die skeduleerder in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition-aanvalle.

## Misbruik van macOS-prosesse

macOS bied baie meganismes waardeur **prosesse met mekaar kan kommunikeer en data kan deel**. Alhoewel hierdie meganismes noodsaaklik is vir normale stelselwerking, kan aanvallers dit misbruik vir injection, kode-uitvoering of toegang tot data.

### Library Injection

Library Injection is ’n tegniek waardeur ’n aanvaller **’n proses dwing om ’n kwaadwillige library te laai**. Sodra dit ingespuit is, loop die library binne die konteks van die teikenproses, wat die aanvaller dieselfde toestemmings en toegang as die proses gee.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking behels **die onderskep van funksie-oproepe** of boodskappe binne sagtewarekode. Deur funksies te hook, kan ’n aanvaller **die gedrag van ’n proses verander**, sensitiewe data waarneem of selfs beheer oor die uitvoeringsvloei verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Hierdie bladsy behandel ARM64-unwind-metadata, arm64e-PAC-beperkings en sintetiese oproepkettings.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waardeur afsonderlike prosesse **data deel en uitruil**. Hoewel IPC vir baie wettige toepassings noodsaaklik is, kan dit ook misbruik word om proses-isolasie te ondermyn, sensitiewe inligting te lek of ongemagtigde handelinge uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-toepassings wat met spesifieke omgewingsveranderlikes uitgevoer word, kan kwesbaar wees vir proses-injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die vlae `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser-aanval** uit te voer, waarmee toetsaanslae, verkeer en koekies gesteel en skripte in bladsye ingespuit kan word...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-lêers **definieer gebruikerskoppelvlak- (UI-)elemente** en hul interaksies binne ’n toepassing. Hulle kan egter **willekeurige opdragte uitvoer**, en **Gatekeeper keer nie** dat ’n reeds uitgevoerde toepassing weer uitgevoer word as ’n **NIB-lêer gewysig is nie**. Daarom kan hulle gebruik word om willekeurige programme willekeurige opdragte te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om JVM-opsies deur **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** in te spuit en ’n Java- of native agent te laai voordat die toepassing begin.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** laai aanvaller-JavaScript vooraf met `--require` (lêer) of `--import data:text/javascript,…` (sonder lêer, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** laai ’n module in ’n interaktiewe REPL, en **`ELECTRON_RUN_AS_NODE`** heraktiveer dit alles op Electron-binêre lêers.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om kode in .NET-toepassings in te spuit deur **`DOTNET_STARTUP_HOOKS`** voor `Main` te gebruik, of deur die .NET-ontfoutingsfunksionaliteit te misbruik wanneer die voorvereistes daarvoor teenwoordig is.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nie-interaktiewe Bash lees **`BASH_ENV`**; interaktiewe POSIX-shells lees **`ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees konfigurasie onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n beheerde opstartlêer uitvoer voordat die bedoelde opdrag uitgevoer word. Bash voer ook ’n opdragvervanging uit wat in **`PS4`** geplaas is wanneer xtrace geaktiveer is (bv. deur geërfde **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Wanneer `/bin/zsh -s` begin word, lees die shell ’n program vanaf standaardinvoer. Daarom verander ’n downloader wat ’n onbetroubare gestruktureerde dokument na die kindproses se stdin kopieer sonder om dit eers te ontleed, die hele dokument in shell-bronkode. Een waargenome loader het ’n openbare iCalendar-lêer reël vir reël deur ’n anonieme pyp gevoer. Kalender-metadata het as opdragte misluk, maar zsh het voortgegaan totdat dit uitvoerbare reëls bereik het wat ná `DESCRIPTION:` geplaas is. Daardie reëls het die volgende toepassingsbundel afgelaai en begin. Die draer se verwagte inhoudtipe en betroubare hosting het dit nie veilig gemaak nie; die gevaarlike grens was om die grepe daarvan aan ’n interpreter oor te dra.<sup>[[5]](#references)</sup>

Verwante stadiums word behandel in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) en [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan beheerde PHP-konfigurasie laai waarvan **`auto_prepend_file`** uitgevoer word voordat die teikenskrip begin.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Die selfstandige Lua-interpreter voer kode of ’n `@file` vanaf **`LUA_INIT`** (of die weergawe-spesifieke variant daarvan) uit voordat die teikenskrip verwerk word.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** herlei na opstartprofiele wat R-kode bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** saam met ’n R-biblioteekpad kan eerder ’n geïnstalleerde pakket outomaties laai.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** herlei na die depot waarvan `config/startup.jl` outomaties uitgevoer word.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** of **`ERL_ZFLAGS`** kan ’n Erlang VM **`-eval`**-uitdrukking inspuit sonder dat ’n payload-lêer nodig is; Elixir-werkladings begin gewoonlik dieselfde VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** herlei na Octave-opstarts­kripte.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` is ’n kruisplatform-.NET-toepassing, en daarom maak verskeie omgewingsveranderlikes uitvoering voor die opdrag moontlik: **`XDG_CONFIG_HOME`** herlei die profielskripte wat met opstart loop, **`PSModulePath`** kaap die outomatiese laai van modules (’n geplante `.psm1` loop tydens invoer en kan ingeboude cmdlets oorskadu), en die .NET-veranderlikes **`CORECLR_PROFILER`**/**`COR_PROFILER`** en **`DOTNET_STARTUP_HOOKS`** laai aanvall kode in die proses voordat `Main` begin.

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

Die standaardbiblioteek-ketting **`PYTHONWARNINGS`** en **`BROWSER`** kan ’n opdrag uitvoer terwyl waarskuwingsfilters ontleed word. ’n Alternatief wat ’n lêer gebruik, plaas `sitecustomize.py` op **`PYTHONPATH`**, sodat normale `site`-inisialisering dit invoer voordat die teikenskrip loop. **`PYTHONBREAKPOINT`** voer ’n gekose callable/module uit wanneer die kode `breakpoint()` bereik. Veranderlikes wat slegs vir interaktiewe gebruik bedoel is, soos **`PYTHONSTARTUP`**, is in minder gevalle toepaslik.

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes gebruik nie, selfs al loop hulle met ’n ingebedde Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (en die `EXINIT`-terugvalopsie daarvan) word tydens normale opstart as Ex-opdragte uitgevoer. Daarom lei `:!cmd` / `:call system(...)` tot kode-uitvoering wanneer ’n slagoffer Vim/Neovim met ’n beheerde omgewing oopmaak:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Afsonderlik installeer Homebrew Python gewoonlik onder `/opt/homebrew`, waar lede van die plaaslike `admin`-groep moontlik die launcher kan vervang. Dit is ’n kaping van ’n skryfbare binêre lêer, nie injection deur ’n omgewingsveranderlike nie; verifieer eienaarskap en ACL’s voordat jy dit as uitbuitbaar beskou.


## Opsporing

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n oopbron-toepassing gebaseer op **EndpointSecurity** wat proses-injection opspoor en blokkeer. Dit is ’n goeie verwysing vir seine wat met Endpoint Security waarneembaar is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-omgewingsveranderlikes** tydens prosesuitvoering: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-oproepe — wanneer een proses die taakpoort van ’n ander versoek, wat ’n voorvereiste is om daarin in te spuit.
- **Electron-ontfoutingsargumente** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron-toepassing in ontfoutingsmodus begin en enigiemand toelaat om daaraan te koppel en kode daarin uit te voer.<sup>[[3]](#references)</sup>
- **Skepping van symlinks/hardlinks oor voorregvlakke heen** — die klassieke primitief: “plant ’n skakel as ’n gewone gebruiker en laat dit na ’n bevoorregte plek wys”. Let daarop dat **symlinks opgespoor kan word, maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die skakelbestemming voor skepping beskikbaar nie.

### Oproepe deur ander prosesse

In [**this blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy lees hoe die funksie **`task_name_for_pid`** gebruik kan word om inligting te kry oor ander **prosesse wat kode in ’n proses inspuit**, en daarna inligting oor daardie ander proses te verkry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** as die een wat die proses uitvoer, of **root**, moet wees om daardie funksie te kan aanroep (en dit gee inligting oor die proses terug, nie ’n manier om kode in te spuit nie).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — oopbron-opsporing van proses-injection op macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-raamwerk](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Waarom Electron-toepassings nie jou geheime vertroulik kan hou nie: --inspect-opsie](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Opsporing van taakwysigings](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - ’n Nuwe weergawe van die MacSync macOS-stealer teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
