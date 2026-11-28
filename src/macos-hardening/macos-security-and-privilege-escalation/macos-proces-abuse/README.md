# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

’n Proses is ’n instansie van ’n uitvoerbare program wat loop, maar prosesse voer nie kode uit nie; dit is drade wat dit doen. Daarom is **prosesse bloot houers vir drade wat loop**, wat geheue, beskrywers, poorte, toestemmings ...

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat ’n presiese kopie van die huidige proses skep. Daarna roep die **kindproses** gewoonlik **`execve`** aan om die nuwe uitvoerbare program te laai en uit te voer. Toe is **`vfork`** bekendgestel om hierdie proses te versnel sonder om geheue te kopieer.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een aanroep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ID’s terug na werklike ID’s
- `POSIX_SPAWN_SETPGROUP`: Stel prosesgroepaffiliasie in
- `POSUX_SPAWN_SETSIGDEF`: Stel verstekgedrag vir seine in
- `POSIX_SPAWN_SETSIGMASK`: Stel seinmasker in
- `POSIX_SPAWN_SETEXEC`: Voer uit in dieselfde proses (soos `execve`, maar met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano-toekenner
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasegmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Maak by verstek alle lêerbeskrywings toe met exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-verskuiwing

Daarbenewens aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die geskepte proses beheer, asook **`posix_spawn_file_actions`**-inskrywings wat lêerbeskrywings wysig.

Wanneer ’n proses sterf, stuur dit die **terugkeerkode na die ouerproses** (as die ouerproses gesterf het, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouerproses moet hierdie waarde met `wait4()` of `waitid()` verkry. Totdat dit gebeur, bly die kindproses in ’n zombie-toestand waarin dit steeds gelys word, maar geen hulpbronne verbruik nie.

### PID’s

PID’s, of prosesidentifiseerders, identifiseer ’n unieke proses. In XNU is die **PID’s** **64-bis**, neem hulle monotonies toe en **vou hulle nooit om nie** (om misbruik te voorkom).

### Prosesgroepe, sessies en koalisies

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Byvoorbeeld, opdragte in ’n shell script sal in dieselfde prosesgroep wees, sodat dit moontlik is om **seine aan almal saam te stuur** deur byvoorbeeld kill te gebruik.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer ’n proses ’n sessie begin (`setsid(2)`), word die kindprosesse binne daardie sessie geplaas, tensy hulle hul eie sessie begin.

’n Koalisie is ’n ander manier om prosesse in Darwin te groepeer. Wanneer ’n proses by ’n koalisie aansluit, kan dit toegang tot poelhulpbronne kry, ’n grootboek deel of aan Jetsam blootgestel word. Koalisies het verskillende rolle: Leader, XPC service, Extension.

### Geloofsbriewe en personas

Elke proses bevat **geloofsbriewe** wat **sy voorregte** in die stelsel **identifiseer**. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander as die binêre lêer die `setuid/setgid`-bis het.\
Daar is verskeie funksies om **nuwe uid’s/gid’s in te stel**.

Die stelseloproep **`persona`** verskaf ’n **alternatiewe** stel **geloofsbriewe**. Wanneer ’n persona aangeneem word, word sy uid, gid en groeplidmaatskappe **gelyktydig** oorgeneem. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) kan die struktuur gevind word:

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

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX threads (`pthreads`), wat deel is van ’n standaard threading-API vir C/C++. Die implementering van pthreads in macOS is in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie biblioteek verskaf die nodige funksies om threads te skep en te bestuur.
2. **Threads skep:** Die `pthread_create()`-funksie word gebruik om nuwe threads te skep. Intern roep hierdie funksie `bsdthread_create()` aan, ’n laervlak-stelseloproep wat spesifiek vir die XNU-kernel is (die kernel waarop macOS gebaseer is). Hierdie stelseloproep neem verskeie vlae wat van `pthread_attr` (eienskappe) afgelei is en wat thread-gedrag spesifiseer, insluitend skeduleringsbeleide en stapelgrootte.
   - **Verstekstapelgrootte:** Die verstekstapelgrootte vir nuwe threads is 512 KB. Dit is voldoende vir tipiese bewerkings, maar kan via thread-eienskappe aangepas word indien meer of minder ruimte nodig is.
3. **Thread-inisialisering:** Die `__pthread_init()`-funksie is noodsaaklik tydens thread-opstelling en gebruik die `env[]`-argument om omgewingsveranderlikes te ontleed, wat besonderhede oor die stapel se ligging en grootte kan insluit.

#### Thread-beëindiging in macOS

1. **Threads verlaat:** Threads word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n thread toe om skoon te verlaat, die nodige opruiming uit te voer en ’n terugkeerwaarde aan enige threads wat daarop wag, terug te stuur.
2. **Thread-opruiming:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` opgeroep om alle gepaardgaande thread-strukture te verwyder. Dit deallokeer Mach-thread-poorte (Mach is die kommunikasiesubstelsel in die XNU-kernel) en roep `bsdthread_terminate` aan, ’n stelseloproep wat die kernelvlakstrukture verwyder wat met die thread geassosieer word.

#### Sinchronisasiemeganismes

Om toegang tot gedeelde hulpbronne te bestuur en wedrenstoestande te vermy, verskaf macOS verskeie sinchronisasieprimitiewe. Dit is noodsaaklik in multithreading-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
   - **Gewone mutex (handtekening: 0x4D555458):** Standaardmutex met ’n geheuevoetspoor van 60 grepe (56 grepe vir die mutex en 4 grepe vir die handtekening).
   - **Vinnige mutex (handtekening: 0x4d55545A):** Soortgelyk aan ’n gewone mutex, maar geoptimaliseer vir vinniger bewerkings, en ook 60 grepe groot.
2. **Toestandveranderlikes:**
   - Word gebruik om vir sekere toestande te wag, en is 44 grepe groot (40 grepe plus ’n handtekening van 4 grepe).
   - **Toestandveranderlike-eienskappe (handtekening: 0x434e4441):** Konfigurasie-eienskappe vir toestandveranderlikes, 12 grepe groot.
3. **Eenmalige veranderlike (handtekening: 0x4f4e4345):**
   - Verseker dat ’n stuk inisialiseringskode slegs een keer uitgevoer word. Dit is 12 grepe groot.
4. **Lees-skryf-slotte:**
   - Laat verskeie lesers of een skrywer op ’n slag toe, wat doeltreffende toegang tot gedeelde data moontlik maak.
   - **Lees-skryf-slot (handtekening: 0x52574c4b):** 196 grepe groot.
   - **Lees-skryf-slot-eienskappe (handtekening: 0x52574c41):** Eienskappe vir lees-skryf-slotte, 20 grepe groot.

> [!TIP]
> Die laaste 4 grepe van daardie objekte word gebruik om oorlope op te spoor.

### Draadplaaslike veranderlikes (TLV)

**Draadplaaslike veranderlikes (TLV)** word in Mach-O-lêers (die formaat vir uitvoerbare lêers in macOS) gebruik om veranderlikes te verklaar wat spesifiek vir **elke thread** in ’n multithread-toepassing is. Dit verseker dat elke thread sy eie afsonderlike instansie van ’n veranderlike het, wat ’n manier bied om konflik te vermy en data-integriteit te handhaaf sonder die behoefte aan eksplisiete sinchronisasiemeganismes soos mutexes.

In C en verwante tale kan jy ’n draadplaaslike veranderlike met die **`__thread`**-sleutelwoord verklaar. So werk dit in jou voorbeeld:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Hierdie kodebrokkie definieer `tlv_var` as ’n thread-local-veranderlike. Elke thread wat hierdie kode uitvoer, het sy eie `tlv_var`, en veranderinge wat een thread aan `tlv_var` maak, beïnvloed nie `tlv_var` in ’n ander thread nie.

In die Mach-O-binêre lêer word die data wat met thread-local-veranderlikes verband hou, in spesifieke afdelings georganiseer:

- **`__DATA.__thread_vars`**: Hierdie afdeling bevat metadata oor die thread-local-veranderlikes, soos hul tipes en initialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie afdeling word gebruik vir thread-local-veranderlikes wat nie uitdruklik geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir data gereserveer is wat met nulle geïnisialiseer word.

Mach-O bied ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local-veranderlikes te bestuur wanneer ’n thread eindig. Met hierdie API kan jy **destructors registreer**—spesiale funksies wat thread-local-data opruim wanneer ’n thread beëindig word.

### Threadprioriteite

Om threadprioriteite te verstaan, moet jy kyk na hoe die bedryfstelsel besluit watter threads en wanneer uitgevoer word. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke thread toegeken is. In macOS en Unix-agtige stelsels word dit bestuur met konsepte soos `nice`, `renice` en Quality of Service (QoS)-klasse.

#### Nice en Renice

1. **Nice:**
   - Die `nice`-waarde van ’n proses is ’n getal wat die prioriteit daarvan beïnvloed. Elke proses het ’n nice-waarde tussen -20 (die hoogste prioriteit) en 19 (die laagste prioriteit). Die verstek-nice-waarde wanneer ’n proses geskep word, is gewoonlik 0.
   - ’n Laer nice-waarde (nader aan -20) maak ’n proses meer “selfsugtig” en gee dit meer CPU-tyd as ander prosesse met hoër nice-waardes.
2. **Renice:**
   - `renice` is ’n opdrag waarmee die nice-waarde van ’n proses wat reeds loop, verander kan word. Dit kan gebruik word om die prioriteit van prosesse dinamies aan te pas, en hul CPU-tydtoekenning te verhoog of te verlaag op grond van nuwe nice-waardes.
   - As ’n proses byvoorbeeld tydelik meer CPU-hulpbronne benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS)-klasse

QoS-klasse is ’n meer moderne benadering tot die bestuur van threadprioriteite, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. Met QoS-klasse kan ontwikkelaars werk **kategoriseer** volgens die belangrikheid of dringendheid daarvan. macOS bestuur threadprioritisering outomaties op grond van hierdie QoS-klasse:

1. **User Interactive:**
   - Hierdie klas is vir take wat tans met die gebruiker in wisselwerking is, of onmiddellike resultate vereis om ’n goeie gebruikerservaring te bied. Hierdie take kry die hoogste prioriteit om die koppelvlak responsief te hou (bv. animasies of gebeurtenishantering).
2. **User Initiated:**
   - Take wat die gebruiker begin en waarvoor hulle onmiddellike resultate verwag, soos om ’n dokument oop te maak of ’n knoppie te klik wat berekeninge vereis. Hierdie take het ’n hoë prioriteit, maar laer as user interactive.
3. **Utility:**
   - Hierdie take loop lank en wys gewoonlik ’n vorderingsaanwyser (bv. om lêers af te laai of data in te voer). Hulle het ’n laer prioriteit as take wat deur die gebruiker begin is, en hoef nie onmiddellik klaar te wees nie.
4. **Background:**
   - Hierdie klas is vir take wat in die agtergrond loop en nie vir die gebruiker sigbaar is nie. Dit kan take soos indeksering, sinkronisering of rugsteun insluit. Hulle het die laagste prioriteit en minimale impak op stelselwerkverrigting.

Met QoS-klasse hoef ontwikkelaars nie die presiese prioriteitsgetalle te bestuur nie; hulle kan eerder op die aard van die taak fokus, waarna die stelsel die CPU-hulpbronne dienooreenkomstig optimaliseer.

Daar is ook verskillende **thread-skeduleringsbeleide** wat ’n stel skeduleringsparameters spesifiseer wat die skeduleerder in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition-aanvalle.

## Misbruik van macOS-prosesse

macOS bied baie meganismes waarmee **prosesse kan interaksie hê, kommunikeer en data deel**. Hoewel hierdie meganismes noodsaaklik is vir normale stelselwerking, kan aanvallers dit misbruik vir injection, kode-uitvoering of datatoegang.

### Library Injection

Library Injection is ’n tegniek waar ’n aanvaller **’n proses dwing om ’n kwaadwillige library te laai**. Sodra dit geïnjekteer is, loop die library binne die konteks van die teikenproses, wat die aanvaller dieselfde toestemmings en toegang as die proses gee.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking behels die **onderskep van funksie-oproepe** of boodskappe binne sagtewarekode. Deur funksies te hook, kan ’n aanvaller die gedrag van ’n proses **verander**, sensitiewe data waarneem of selfs beheer oor die uitvoeringsvloei verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Hierdie bladsy dek ARM64-unwind-metadata, arm64e PAC-beperkings en sintetiese oproepkettings.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waarmee afsonderlike prosesse **data deel en uitruil**. Hoewel IPC vir baie wettige toepassings noodsaaklik is, kan dit ook misbruik word om proses-isolasie te ondermyn, sensitiewe inligting te lek of ongemagtigde handelinge uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-toepassings wat met spesifieke omgewingsveranderlikes uitgevoer word, kan kwesbaar wees vir proses-injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die vlae `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser-aanval** uit te voer, wat dit moontlik maak om toetsaanslae, verkeer en koekies te steel, scripts in bladsye te injecteer, ens.:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-lêers **definieer gebruikerskoppelvlakelemente (UI)** en hul interaksies binne ’n toepassing. Hulle kan egter **willekeurige opdragte uitvoer**, en **Gatekeeper keer nie dat ’n reeds uitgevoerde toepassing weer uitgevoer word** as ’n **NIB-lêer gewysig is**. Daarom kan hulle gebruik word om willekeurige programme willekeurige opdragte te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om JVM-opsies deur **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** te injecteer en ’n Java- of native agent te laai voordat die toepassing begin.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** laai aanvaller-JavaScript vooraf met `--require` (lêer) of `--import data:text/javascript,…` (lêerloos, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** laai ’n module in ’n interaktiewe REPL, en **`ELECTRON_RUN_AS_NODE`** aktiveer dit alles weer op Electron-binêre lêers.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om kode in .NET-toepassings te injecteer met **`DOTNET_STARTUP_HOOKS`** voor `Main`, of deur die .NET-ontfoutingsfunksionaliteit te misbruik wanneer die nodige voorvereistes aanwesig is.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nie-interaktiewe Bash lees **`BASH_ENV`**; interaktiewe POSIX-shells lees **`ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees konfigurasie onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n beheerde opstartlêer uitvoer voordat die bedoelde opdrag loop. Bash voer ook ’n command substitution uit wat in **`PS4`** geplaas is wanneer xtrace geaktiveer is (bv. oorgeërfde **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Wanneer `/bin/zsh -s` begin word, lees die shell ’n program vanaf standaardinvoer. ’n Downloader wat dus ’n onbetroubare gestruktureerde dokument na die child se stdin kopieer sonder om dit eers te ontleed, het die hele dokument in shell-bronkode verander. Een waargenome loader het ’n openbare iCalendar-lêer reël vir reël deur ’n anonieme pyp gevoer. Die kalender-metadata het as opdragte misluk, maar zsh het voortgegaan totdat dit uitvoerbare reëls ná `DESCRIPTION:` bereik het. Dié reëls het die volgende toepassingsbundel afgelaai en begin. Die draer se verwagte inhoudtipe en betroubare hosting het dit nie veilig gemaak nie; die gevaarlike grens was dat die grepe daarvan aan ’n interpreter deurgegee is.<sup>[[5]](#references)</sup>

Verwante fases word gedek in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), en [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan beheerde PHP-konfigurasie laai waarvan **`auto_prepend_file`** uitgevoer word voordat die teikenscript begin.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Die selfstandige Lua-interpreter voer kode of ’n `@file` vanaf **`LUA_INIT`** (of die weergawe-spesifieke variant daarvan) uit voordat die teikenscript verwerk word.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** herlei na opstartprofiele wat R-kode bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, tesame met ’n R-biblioteekpad, kan eerder ’n geïnstalleerde pakket outomaties laai.

[R startup profiles and package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** herlei na die depot waarvan `config/startup.jl` outomaties uitgevoer word.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** of **`ERL_ZFLAGS`** kan ’n Erlang VM **`-eval`**-uitdrukking injecteer sonder dat ’n payload-lêer nodig is; Elixir-werkladings begin gewoonlik dieselfde VM.

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** herlei na Octave-opstartscripts.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` is ’n kruisplatform-.NET-toepassing, dus kan verskeie omgewingsveranderlikes kode-uitvoering voor die opdrag moontlik maak: **`XDG_CONFIG_HOME`** herlei na die profielscripts wat by opstart loop, **`PSModulePath`** kaap outomatiese modulelaaiing (’n geplante `.psm1` loop wanneer dit ingevoer word en kan ingeboude cmdlets oorskadu), en die .NET-veranderlikes **`CORECLR_PROFILER`**/**`COR_PROFILER`** en **`DOTNET_STARTUP_HOOKS`** laai aanvallerskode in die proses voordat `Main` begin.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende opsies om ’n Perl-script willekeurige kode te laat uitvoer in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om Ruby-omgewingsveranderlikes (**`RUBYOPT`**, **`RUBYLIB`**) te misbruik om willekeurige scripts willekeurige kode te laat uitvoer:


[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Die standaardbiblioteekketting **`PYTHONWARNINGS`** en **`BROWSER`** kan ’n opdrag uitvoer tydens die ontleding van waarskuwingsfilters. ’n Lêergebaseerde alternatief plaas `sitecustomize.py` op **`PYTHONPATH`**, sodat normale `site`-initialisering dit invoer voordat die teikenscript begin. **`PYTHONBREAKPOINT`** voer ’n gekose callable/module uit wanneer die kode `breakpoint()` bereik.

Op CPython 3.13 en nuwer kan **`PYTHONINSPECT`** ook ’n **`PYTHONSTARTUP`**-lêer ná ’n script uitvoer wanneer sy PyREPL op ’n terminaal begin.<sup>[[6]](#references)</sup>

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes gebruik nie, selfs wanneer hulle ’n ingebedde Python gebruik.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (en sy terugvalopsie `EXINIT`) word as Ex-opdragte uitgevoer tydens normale opstart, dus lei `:!cmd` / `:call system(...)` tot kode-uitvoering wanneer ’n slagoffer Vim/Neovim met ’n beheerde omgewing oopmaak:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Afsonderlik installeer Homebrew Python dikwels onder `/opt/homebrew`, waar lede van die plaaslike `admin`-groep moontlik die launcher kan vervang. Dit is ’n kaping van ’n skryfbare binêre lêer, nie injection via ’n omgewingsveranderlike nie; verifieer eienaarskap en ACL’s voordat jy dit as uitbuitbaar beskou.


## Opsporing

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n oopbron-toepassing wat op **EndpointSecurity** gebaseer is en proses-injection opspoor en blokkeer. Dit is ’n goeie verwysing vir seine wat via Endpoint Security waarneembaar is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-omgewingsveranderlikes** tydens prosesuitvoering: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-oproepe — een proses wat ’n ander se taakpoort versoek, wat ’n voorvereiste is om daarin te injecteer.
- **Electron-ontfoutingsargumente** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron-toepassing in ontfoutingsmodus begin en enigiemand toelaat om daaraan te koppel en kode daarin uit te voer.<sup>[[3]](#references)</sup>
- **Skep van symlinks/hardlinks oor voorregvlakke heen** — die klassieke primitief: “plaas ’n skakel as ’n gewone gebruiker en laat dit na ’n bevoorregte ligging wys”. Let daarop dat **symlinks opgespoor kan word, maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die skakelbestemming bloot voordat dit geskep word nie.

### Oproepe deur ander prosesse

In [**this blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy lees hoe die funksie **`task_name_for_pid`** gebruik kan word om inligting te kry oor ander **prosesse wat kode in ’n proses injecteer**, en daarna inligting oor daardie ander proses te bekom.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** moet hê as die gebruiker wat die proses uitvoer, of **root** moet wees, om daardie funksie aan te roep (en dit gee inligting oor die proses terug, nie ’n manier om kode te injecteer nie).



## References

- [1] [Shield — oopbron-macOS-opsporing van proses-injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-raamwerk](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Waarom Electron-toepassings nie jou geheime vertroulik kan stoor nie: --inspect-opsie](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Opsporing van taakwysigings](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - ’n Nuwe weergawe van die MacSync-macOS-steler teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
- [6] [Python-opdragreël en omgewing — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
