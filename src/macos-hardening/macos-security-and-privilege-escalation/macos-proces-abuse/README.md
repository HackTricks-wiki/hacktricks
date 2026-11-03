# macOS-prosesmisbruik

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

’n Proses is ’n instansie van ’n uitvoerbare program wat loop; prosesse voer egter nie kode uit nie, maar threads. Daarom is **prosesse bloot houers vir threads wat loop**, en verskaf hulle geheue, beskrywers, poorte, toestemmings...

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat ’n presiese kopie van die huidige proses sou skep. Daarna sou die **kindproses** gewoonlik **`execve`** aanroep om die nuwe uitvoerbare program te laai en uit te voer. Toe is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder om geheue te kopieer.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een oproep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ID's terug na werklike ID's
- `POSIX_SPAWN_SETPGROUP`: Stel prosesgroepverband in
- `POSUX_SPAWN_SETSIGDEF`: Stel die verstekgedrag vir seine in
- `POSIX_SPAWN_SETSIGMASK`: Stel die seingemasker in
- `POSIX_SPAWN_SETEXEC`: Voer uit in dieselfde proses (soos `execve`, maar met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano-toeëiener
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasegmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Maak alle lêerbeskrywings by verstek toe tydens exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-skuifwaarde

Boonop aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die voortgebragte proses beheer, asook **`posix_spawn_file_actions`**-inskrywings wat lêerbeskrywings wysig.

Wanneer ’n proses sterf, stuur dit die **terugkeerkode na die ouerproses** (as die ouerproses gesterf het, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouerproses moet hierdie waarde verkry deur `wait4()` of `waitid()` aan te roep. Totdat dit gebeur, bly die kind in ’n zombie-toestand: dit word steeds gelys, maar gebruik geen hulpbronne nie.

### PID's

PID's, of prosesidentifiseerders, identifiseer ’n unieke proses. In XNU is die **PID's** **64-bis**, neem hulle monotoon toe en **rol hulle nooit oor nie** (om misbruik te voorkom).

### Prosesgroepe, sessies en koalisies

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in ’n dopskrip sal byvoorbeeld in dieselfde prosesgroep wees, sodat dit moontlik is om **seine gelyktydig aan hulle te stuur**, byvoorbeeld deur `kill` te gebruik.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer ’n proses ’n sessie begin (`setsid(2)`), word die kinderprosesse binne daardie sessie geplaas, tensy hulle hul eie sessie begin.

’n Koalisie is nog ’n manier om prosesse in Darwin te groepeer. Wanneer ’n proses by ’n koalisie aansluit, kan dit toegang tot poelhulpbronne verkry, ’n grootboek deel of aan Jetsam onderwerp word. Koalisies het verskillende rolle: Leier, XPC-diens, Uitbreiding.

### Geloofsbriewe en personas

Elke proses hou **geloofsbriewe** wat sy **voorregte** in die stelsel **identifiseer**. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander as die binêre lêer die `setuid/setgid`-bis het.\
Daar is verskeie funksies om **nuwe uid's/gid's in te stel**.

Die stelseloproep **`persona`** verskaf ’n **alternatiewe** stel **geloofsbriewe**. Wanneer ’n persona aangeneem word, word die uid, gid en groeplidmaatskappe daarvan **gelyktydig** oorgeneem. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) is dit moontlik om die struktuur te vind:

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

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX-drade (`pthreads`), wat deel is van ’n standaard draad-API vir C/C++. Die implementering van pthreads in macOS is in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie biblioteek verskaf die nodige funksies om drade te skep en te bestuur.
2. **Drade skep:** Die `pthread_create()`-funksie word gebruik om nuwe drade te skep. Intern roep hierdie funksie `bsdthread_create()` aan, ’n laervlakstelseloproep wat spesifiek vir die XNU-kern (die kern waarop macOS gebaseer is) is. Hierdie stelseloproep neem verskeie vlae wat van `pthread_attr` (eienskappe) afgelei word en draadinligting spesifiseer, waaronder skeduleringsbeleide en stapelgrootte.
   - **Verstekstapelgrootte:** Die verstekstapelgrootte vir nuwe drade is 512 KB, wat voldoende is vir tipiese bewerkings, maar met draadkenmerke aangepas kan word indien meer of minder ruimte nodig is.
3. **Draadinitialisering:** Die `__pthread_init()`-funksie is noodsaaklik tydens draadopstelling en gebruik die `env[]`-argument om omgewingsveranderlikes te ontleed, wat besonderhede oor die stapel se ligging en grootte kan insluit.

#### Beëindiging van drade in macOS

1. **Drade verlaat:** Drade word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n draad skoon afsluit, die nodige opruiming uitvoer en ’n terugkeerwaarde aan enige drade wat daarop wag, terugstuur.
2. **Draadopruiming:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` aangeroep. Dit hanteer die verwydering van alle verwante draadstrukture. Dit deallokeer Mach-draadpoorte (Mach is die kommunikasiestelsel in die XNU-kern) en roep `bsdthread_terminate` aan, ’n syscall wat die kernvlakstrukture verwyder wat met die draad verband hou.

#### Sinkronisasiemeganismes

Om toegang tot gedeelde hulpbronne te bestuur en wedrenvoorwaardes te vermy, verskaf macOS verskeie sinkronisasieprimitiewe. Dit is noodsaaklik in omgewings met veelvuldige drade om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
   - **Gewone mutex (handtekening: 0x4D555458):** Standaardmutex met ’n geheuevoetspoor van 60 grepe (56 grepe vir die mutex en 4 grepe vir die handtekening).
   - **Vinnige mutex (handtekening: 0x4d55545A):** Soortgelyk aan ’n gewone mutex, maar geoptimaliseer vir vinniger bewerkings; ook 60 grepe groot.
2. **Voorwaardeveranderlikes:**
   - Word gebruik om vir sekere voorwaardes te wag en is 44 grepe groot (40 grepe plus ’n 4-greep-handtekening).
   - **Voorwaardeveranderlike-kenmerke (handtekening: 0x434e4441):** Konfigurasiekenmerke vir voorwaardeveranderlikes, 12 grepe groot.
3. **Eenmalige veranderlike (handtekening: 0x4f4e4345):**
   - Verseker dat ’n stuk initialiseringskode slegs een keer uitgevoer word. Dit is 12 grepe groot.
4. **Lees-skryf-slotte:**
   - Laat verskeie lesers of een skrywer op ’n slag toe en maak doeltreffende toegang tot gedeelde data moontlik.
   - **Lees-skryf-slot (handtekening: 0x52574c4b):** 196 grepe groot.
   - **Lees-skryf-slot-kenmerke (handtekening: 0x52574c41):** Kenmerke vir lees-skryf-slotte, 20 grepe groot.

> [!TIP]
> Die laaste 4 grepe van hierdie objekte word gebruik om oorlope op te spoor.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** word in Mach-O-lêers (die formaat vir uitvoerbare lêers in macOS) gebruik om veranderlikes te verklaar wat spesifiek vir **elke draad** in ’n toepassing met veelvuldige drade is. Dit verseker dat elke draad sy eie afsonderlike instansie van ’n veranderlike het, wat help om konflik te vermy en data-integriteit te handhaaf sonder dat eksplisiete sinkronisasiemeganismes soos mutexes nodig is.

In C en verwante tale kan jy ’n draadplaaslike veranderlike met die sleutelwoord **`__thread`** verklaar. Só werk dit in jou voorbeeld:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Hierdie brokkie definieer `tlv_var` as ’n thread-local-veranderlike. Elke thread wat hierdie kode uitvoer, het sy eie `tlv_var`, en veranderinge wat een thread aan `tlv_var` maak, beïnvloed nie `tlv_var` in ’n ander thread nie.

In die Mach-O-binêre lêer word data wat met thread-local-veranderlikes verband hou, in spesifieke afdelings georganiseer:

- **`__DATA.__thread_vars`**: Hierdie afdeling bevat metadata oor die thread-local-veranderlikes, soos hul tipes en inisialiseringsstatus.
- **`__DATA.__thread_bss`**: Hierdie afdeling word gebruik vir thread-local-veranderlikes wat nie eksplisiet geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir data gereserveer is wat met nulle geïnisialiseer word.

Mach-O verskaf ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local-veranderlikes te bestuur wanneer ’n thread eindig. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local-data opruim wanneer ’n thread eindig.

### Draadprioriteite

Om draadprioriteite te verstaan, moet jy kyk hoe die bedryfstelsel besluit watter drade moet loop en wanneer. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke draad toegeken is. In macOS en Unix-agtige stelsels word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS)-klasse.

#### Nice en Renice

1. **Nice:**
   - Die `nice`-waarde van ’n proses is ’n getal wat sy prioriteit beïnvloed. Elke proses het ’n nice-waarde van -20 (die hoogste prioriteit) tot 19 (die laagste prioriteit). Die verstek-nice-waarde wanneer ’n proses geskep word, is gewoonlik 0.
   - ’n Laer nice-waarde (nader aan -20) maak ’n proses meer “selfsugtig” en gee dit meer SVE-tyd as ander prosesse met hoër nice-waardes.
2. **Renice:**
   - `renice` is ’n opdrag waarmee die nice-waarde van ’n proses wat reeds loop, verander kan word. Dit kan gebruik word om die prioriteit van prosesse dinamies aan te pas deur hul SVE-tydtoewysing te verhoog of te verlaag op grond van nuwe nice-waardes.
   - As ’n proses byvoorbeeld tydelik meer SVE-hulpbronne benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS)-klasse

QoS-klasse is ’n meer moderne benadering om draadprioriteite te hanteer, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS-klasse laat ontwikkelaars toe om werk in verskillende vlakke te **kategoriseer** volgens die belangrikheid of dringendheid daarvan. macOS bestuur draadprioritisering outomaties op grond van hierdie QoS-klasse:

1. **User Interactive:**
   - Hierdie klas is vir take wat tans met die gebruiker kommunikeer of onmiddellike resultate vereis om ’n goeie gebruikerservaring te verseker. Hierdie take kry die hoogste prioriteit sodat die koppelvlak responsief bly (bv. animasies of gebeurtenishantering).
2. **User Initiated:**
   - Take wat die gebruiker begin en waarvoor onmiddellike resultate verwag word, soos om ’n dokument oop te maak of op ’n knoppie te klik wat berekeninge vereis. Hierdie take het ’n hoë prioriteit, maar laer as user interactive.
3. **Utility:**
   - Hierdie take loop lank en vertoon gewoonlik ’n vorderingsaanwyser (bv. die aflaai van lêers of die invoer van data). Hulle het ’n laer prioriteit as user-initiated-take en hoef nie onmiddellik klaar te wees nie.
4. **Background:**
   - Hierdie klas is vir take wat in die agtergrond loop en nie vir die gebruiker sigbaar is nie. Dit kan take soos indeksering, sinchronisering of rugsteun insluit. Hulle het die laagste prioriteit en minimale invloed op stelselwerkverrigting.

Met QoS-klasse hoef ontwikkelaars nie die presiese prioriteitsgetalle te bestuur nie, maar kan hulle eerder op die aard van die taak fokus. Die stelsel optimaliseer dan die SVE-hulpbronne dienooreenkomstig.

Daar is ook verskillende **draadskeduleringsbeleide** wat ’n stel skeduleringsparameters spesifiseer wat die skeduleerder in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition-aanvalle.

## macOS-prosesmisbruik

macOS bied baie meganismes vir **prosesse om met mekaar te kommunikeer en data te deel**. Hoewel hierdie meganismes noodsaaklik is vir normale stelselwerking, kan aanvallers dit misbruik vir inspuiting, kode-uitvoering of datatoegang.

### Library Injection

Library Injection is ’n tegniek waarin ’n aanvaller **’n proses dwing om ’n kwaadwillige biblioteek te laai**. Ná inspuiting loop die biblioteek binne die konteks van die teikenproses, wat die aanvaller dieselfde toestemmings en toegang as die proses gee.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking behels dat **funksie-oproepe** of boodskappe binne sagtewarekode onderskep word. Deur funksies te hook, kan ’n aanvaller **die gedrag** van ’n proses verander, sensitiewe data waarneem of selfs beheer oor die uitvoeringsvloei verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Hierdie bladsy dek ARM64-unwind-metadata, arm64e PAC-beperkings en sintetiese oproepkettings.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waarmee afsonderlike prosesse **data deel en uitruil**. Hoewel IPC noodsaaklik is vir baie wettige toepassings, kan dit ook misbruik word om proses-isolasie te ondermyn, sensitiewe inligting te lek of ongemagtigde handelinge uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-toepassings wat met spesifieke omgewingsveranderlikes uitgevoer word, kan kwesbaar wees vir prosesinspuiting:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die vlae `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser attack** uit te voer, wat dit moontlik maak om toetsaanslae, verkeer en koekies te steel, skrifte in bladsye in te spuit, ensovoorts:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-lêers **definieer gebruikerskoppelvlak- (UI-) elemente** en hul interaksies binne ’n toepassing. Hulle kan egter **willekeurige opdragte uitvoer**, en **Gatekeeper keer nie** dat ’n reeds uitgevoerde toepassing weer uitgevoer word as ’n **NIB-lêer gewysig word nie**. Daarom kan hulle gebruik word om willekeurige programme willekeurige opdragte te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om JVM-opsies deur **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** in te spuit en ’n Java- of native agent te laai voordat die toepassing begin.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** laai aanvaller-JavaScript vooraf via `--require` (lêer) of `--import data:text/javascript,…` (sonder ’n lêer, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** laai ’n module in ’n interaktiewe REPL, en **`ELECTRON_RUN_AS_NODE`** heraktiveer dit alles op Electron-binêre lêers.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om kode in .NET-toepassings in te spuit deur **`DOTNET_STARTUP_HOOKS`** voor `Main`, of deur die .NET-ontfoutingsfunksionaliteit te misbruik wanneer die vereistes daarvoor nagekom word.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nie-interaktiewe Bash lees **`BASH_ENV`**; interaktiewe POSIX-skulpe lees **`ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees konfigurasie onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n beheerde opstartlêer uitvoer voordat die bedoelde opdrag uitgevoer word. Bash voer ook ’n opdragvervanging uit wat in **`PS4`** geplaas is wanneer xtrace geaktiveer is (bv. deur oorgeërfde **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

As jy `/bin/zsh -s` begin, lees die shell ’n program vanaf standaardinvoer. Daarom verander ’n aflaaiprogram wat ’n onbetroubare gestruktureerde dokument na die kindproses se stdin kopieer sonder om dit eers te ontleed, die hele dokument in shell-bronkode. Een waargenome loader het ’n openbare iCalendar-lêer reël vir reël deur ’n anonieme pyp gevoer. Kalendermetadata het as opdragte misluk, maar zsh het voortgegaan totdat dit uitvoerbare reëls ná `DESCRIPTION:` bereik het. Hierdie reëls het die volgende toepassingsbundel afgelaai en begin. Die draer se verwagte inhoudtipe en vertroude gasheer het dit nie veilig gemaak nie; die gevaarlike grens was om die grepe daarvan aan ’n interpreter deur te gee.<sup>[[5]](#references)</sup>

Verwante stadiums word gedek in [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) en [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan beheerde PHP-konfigurasie laai waarvan **`auto_prepend_file`** uitgevoer word voordat die teikenskrip begin.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Die selfstandige Lua-interpreter voer kode of ’n `@file` vanaf **`LUA_INIT`** (of die weergawe-spesifieke variant daarvan) uit voordat die teikenskrip verwerk word.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** herlei na opstartprofiele wat R-kode bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** kan, saam met ’n R-biblioteekpad, eerder ’n geïnstalleerde pakket outomaties laai.

[R startup profiles and package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** herlei na die depot waarvan `config/startup.jl` outomaties uitgevoer word.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** of **`ERL_ZFLAGS`** kan ’n Erlang VM **`-eval`**-uitdrukking inspuit sonder dat ’n loonvraglêer nodig is; Elixir-werkladings begin gewoonlik dieselfde VM.

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** herlei na Octave-opstelskripte.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` is ’n kruisplatform-.NET-toepassing, dus maak verskeie omgewingsveranderlikes voor-opdraguitvoering moontlik: **`XDG_CONFIG_HOME`** herlei die profielskripte wat tydens opstart loop, **`PSModulePath`** kaap outomatiese modulelaaiing (’n geplante `.psm1` loop tydens invoer en kan ingeboude cmdlets oorskadu), en die .NET-veranderlikes **`CORECLR_PROFILER`**/**`COR_PROFILER`** en **`DOTNET_STARTUP_HOOKS`** laai aanvallerkode in die proses voordat `Main` begin.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende opsies om ’n Perl-skrip willekeurige kode te laat uitvoer:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om Ruby-omgewingsveranderlikes (**`RUBYOPT`**, **`RUBYLIB`**) te misbruik om willekeurige skripte willekeurige kode te laat uitvoer:


[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Die **`PYTHONWARNINGS`**- en **`BROWSER`**-standaardbiblioteekketting kan ’n opdrag uitvoer tydens die ontleding van waarskuwingsfilters. ’n Alternatief wat ’n lêer gebruik, plaas `sitecustomize.py` op **`PYTHONPATH`**, sodat normale `site`-inisialisering dit invoer voordat die teikenskrip begin. **`PYTHONBREAKPOINT`** voer ’n gekose callable/module uit wanneer die kode `breakpoint()` bereik. Veranderlikes wat slegs interaktief gebruik word, soos **`PYTHONSTARTUP`**, is in minder gevalle toepaslik.

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes gebruik nie, selfs wanneer hulle ’n ingebedde Python gebruik.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (en die `EXINIT`-terugvalopsie) word tydens ’n normale opstart as Ex-opdragte uitgevoer. `:!cmd` / `:call system(...)` kan dus kode uitvoer wanneer ’n slagoffer Vim/Neovim met ’n beheerde omgewing oopmaak:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Afsonderlik installeer Homebrew Python dikwels onder `/opt/homebrew`, waar lede van die plaaslike `admin`-groep die launcher moontlik kan vervang. Dit is ’n kaping van ’n skryfbare binêre lêer eerder as inspuiting deur ’n omgewingsveranderlike; verifieer eienaarskap en ACL’s voordat jy dit as uitbuitbaar beskou.


## Opsporing

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n oopbron-toepassing wat op **EndpointSecurity** gebaseer is en prosesinspuiting opspoor en blokkeer. Dit is ’n goeie verwysing vir die seine wat deur Endpoint Security waargeneem kan word, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Inspuitingsomgewingsveranderlikes** tydens prosesuitvoering: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-oproepe — een proses wat ’n ander proses se taakpoort aanvra, wat ’n voorvereiste is om daarin in te spuit.
- **Electron-ontfoutingsargumente** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron-toepassing in ontfoutingsmodus begin en enigiemand toelaat om daaraan te koppel en kode daarin uit te voer.<sup>[[3]](#references)</sup>
- **Skep van simboliese/skakels met harde skakels oor voorregvlakke heen** — die klassieke primitief: “plaas ’n skakel as ’n gewone gebruiker en laat dit na ’n bevoorregte ligging wys”. Let daarop dat **simboliese skakels opgespoor, maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die skakelbestemming voor die skep daarvan bloot nie.

### Oproepe deur ander prosesse

In [**hierdie blogplasing**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy lees hoe die funksie **`task_name_for_pid`** gebruik kan word om inligting te kry oor ander **prosesse wat kode in ’n proses inspuit**, en daarna inligting oor daardie ander proses te kry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** as die gebruiker wat die proses uitvoer of **root** moet wees om daardie funksie te kan aanroep (en dit gee inligting oor die proses terug, nie ’n manier om kode in te spuit nie).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — oopbrondetectie van macOS-prosesinspuiting (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-raamwerk](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Waarom Electron-toepassings nie jou geheime vertroulik kan hou nie: --inspect-opsie](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Opsporing van taakwysigings](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - ’n Nuwe weergawe van die MacSync macOS-dief teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
