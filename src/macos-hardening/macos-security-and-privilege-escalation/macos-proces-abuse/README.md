# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

'n Proses is 'n instansie van 'n uitvoerbare lêer wat loop; prosesse voer egter nie kode uit nie — dit is threads wat dit doen. Daarom is **prosesse bloot houers vir threads wat loop**, wat geheue, descriptors, poorte, toestemmings...

Tradisioneel is prosesse binne ander prosesse (behalwe PID 1) begin deur **`fork`** aan te roep, wat 'n presiese kopie van die huidige proses skep. Daarna het die **child process** gewoonlik **`execve`** aangeroep om die nuwe uitvoerbare lêer te laai en dit te laat loop. Toe is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder enige geheuekopiëring.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een oproep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ID's terug na werklike ID's
- `POSIX_SPAWN_SETPGROUP`: Stel prosesgroepaffiliasie in
- `POSUX_SPAWN_SETSIGDEF`: Stel die verstekgedrag van seine in
- `POSIX_SPAWN_SETSIGMASK`: Stel seingemasker in
- `POSIX_SPAWN_SETEXEC`: Voer uit in dieselfde proses (soos `execve`, met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasegmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Maak alle lêerbeskrywings by verstek toe met exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-skuifwaarde

Verder aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die geskepte proses beheer, en **`posix_spawn_file_actions`**-inskrywings wat lêerbeskrywings wysig.

Wanneer 'n proses sterf, stuur dit die **retourkode aan die ouerproses** (as die ouerproses gesterf het, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouerproses moet hierdie waarde kry deur `wait4()` of `waitid()` aan te roep. Totdat dit gebeur, bly die child in 'n zombie-toestand waarin dit steeds gelys word, maar geen hulpbronne verbruik nie.

### PIDs

PIDs, oftewel prosesidentifiseerders, identifiseer 'n unieke proses. In XNU is **PIDs** **64-bis**, neem hulle monotoon toe en **rol hulle nooit om nie** (om misbruik te voorkom).

### Prosesgroepe, sessies en Coalitions

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in 'n shell script sal byvoorbeeld in dieselfde prosesgroep wees, sodat dit moontlik is om **seine gelyktydig aan hulle te stuur**, byvoorbeeld deur kill te gebruik.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer 'n proses 'n sessie begin (`setsid(2)`), word die child-prosesse binne die sessie geplaas, tensy hulle hul eie sessie begin.

Coalition is nog 'n manier om prosesse in Darwin te groepeer. Wanneer 'n proses by 'n Coalition aansluit, kan dit toegang tot poelhulpbronne kry, 'n grootboek deel of deur Jetsam geraak word. Coalitions het verskillende rolle: Leader, XPC service, Extension.

### Geloofsbriewe en personae

Elke proses hou **geloofsbriewe** wat sy **regte in die stelsel identifiseer**. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander as die binêre lêer die `setuid/setgid`-bit het.\
Daar is verskeie funksies om **nuwe uids/gids in te stel**.

Die syscall **`persona`** bied 'n **alternatiewe** stel **geloofsbriewe**. Deur 'n persona aan te neem, word die uid, gid en groeplidmaatskappe daarvan **gelyktydig** oorgeneem. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) is dit moontlik om die struct te vind:

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
2. **Drade skep:** Die `pthread_create()`-funksie word gebruik om nuwe drade te skep. Intern roep hierdie funksie `bsdthread_create()` aan, ’n laervlak-stelseloproep wat spesifiek vir die XNU-kern is (die kern waarop macOS gebaseer is). Hierdie stelseloproep neem verskeie vlae, afgelei van `pthread_attr` (eienskappe), wat die draad se gedrag spesifiseer, insluitend skeduleringsbeleide en stapelgrootte.
   - **Verstekstapelgrootte:** Die verstekstapelgrootte vir nuwe drade is 512 KB. Dit is voldoende vir tipiese bewerkings, maar kan via draadeienskappe aangepas word indien meer of minder ruimte nodig is.
3. **Draadinisialisering:** Die `__pthread_init()`-funksie is belangrik tydens draadopstelling. Dit gebruik die `env[]`-argument om omgewingsveranderlikes te ontleed, wat besonderhede oor die stapel se ligging en grootte kan insluit.

#### Draadbeëindiging in macOS

1. **Drade beëindig:** Drade word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n draad skoon afsluit, die nodige opruiming uitvoer en ’n terugkeerwaarde aan enige drade wat daarop wag, stuur.
2. **Draadoopruiming:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` opgeroep. Dit hanteer die verwydering van alle geassosieerde draadstrukture. Dit deallokeer Mach-draadpoorte (Mach is die kommunikasiesubstelsel in die XNU-kern) en roep `bsdthread_terminate` aan, ’n stelseloproep wat die kernvlakstrukture verwyder wat met die draad geassosieer word.

#### Sinchronisasiemeganismes

Om toegang tot gedeelde hulpbronne te bestuur en resiestoestande te voorkom, bied macOS verskeie sinchronisasieprimitiewe. Dit is noodsaaklik in multithread-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
   - **Gewone mutex (handtekening: 0x4D555458):** Standaardmutex met ’n geheuevoetspoor van 60 grepe (56 grepe vir die mutex en 4 grepe vir die handtekening).
   - **Vinnige mutex (handtekening: 0x4d55545A):** Soortgelyk aan ’n gewone mutex, maar geoptimaliseer vir vinniger bewerkings; dit is ook 60 grepe groot.
2. **Voorwaardeveranderlikes:**
   - Word gebruik om vir sekere voorwaardes te wag, en is 44 grepe groot (40 grepe plus ’n handtekening van 4 grepe).
   - **Voorwaardeveranderlike-eienskappe (handtekening: 0x434e4441):** Konfigurasie-eienskappe vir voorwaardeveranderlikes, 12 grepe groot.
3. **Eenmalige veranderlike (handtekening: 0x4f4e4345):**
   - Verseker dat ’n stuk inisialiseringskode slegs een keer uitgevoer word. Dit is 12 grepe groot.
4. **Lees-skryf-slotte:**
   - Laat verskeie lesers of een skrywer op ’n slag toe, wat doeltreffende toegang tot gedeelde data moontlik maak.
   - **Lees-skryf-slot (handtekening: 0x52574c4b):** 196 grepe groot.
   - **Lees-skryf-slot-eienskappe (handtekening: 0x52574c41):** Eienskappe vir lees-skryf-slotte, 20 grepe groot.

> [!TIP]
> Die laaste 4 grepe van hierdie objekte word gebruik om oorlope op te spoor.

### Draadplaaslike veranderlikes (TLV)

**Draadplaaslike veranderlikes (TLV)** word in Mach-O-lêers (die formaat vir uitvoerbare lêers in macOS) gebruik om veranderlikes te verklaar wat spesifiek vir **elke draad** in ’n multithread-toepassing is. Dit verseker dat elke draad sy eie afsonderlike instansie van ’n veranderlike het. So kan konflikte vermy en data-integriteit gehandhaaf word sonder dat eksplisiete sinchronisasiemeganismes soos mutexes nodig is.

In C en verwante tale kan jy ’n draadplaaslike veranderlike met die sleutelwoord **`__thread`** verklaar. Só werk dit in jou voorbeeld:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Hierdie snippet definieer `tlv_var` as ’n thread-local variable. Elke thread wat hierdie kode uitvoer, het sy eie `tlv_var`, en veranderinge wat een thread aan `tlv_var` maak, beïnvloed nie `tlv_var` in ’n ander thread nie.

In die Mach-O-binary word data wat met thread-local variables verband hou, in spesifieke afdelings georganiseer:

- **`__DATA.__thread_vars`**: Hierdie afdeling bevat metadata oor die thread-local variables, soos hul tipes en initialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie afdeling word gebruik vir thread-local variables wat nie eksplisiet geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir nul-geïnisialiseerde data gereserveer is.

Mach-O bied ook ’n spesifieke API, **`tlv_atexit`**, om thread-local variables te bestuur wanneer ’n thread eindig. Met hierdie API kan jy **destructors registreer**—spesiale funksies wat thread-local data opruim wanneer ’n thread eindig.

### Threadprioriteite

Om threadprioriteite te verstaan, moet jy kyk na hoe die bedryfstelsel besluit watter threads wanneer loop. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke thread toegeken is. In macOS- en Unix-agtige stelsels word dit hanteer deur konsepte soos `nice`, `renice` en Quality of Service (QoS)-klasse.

#### Nice en Renice

1. **Nice:**
   - Die `nice`-waarde van ’n proses is ’n getal wat die prioriteit daarvan beïnvloed. Elke proses het ’n nice-waarde wat wissel van -20 (die hoogste prioriteit) tot 19 (die laagste prioriteit). Die verstek-nice-waarde wanneer ’n proses geskep word, is gewoonlik 0.
   - ’n Laer nice-waarde (nader aan -20) maak ’n proses meer “selfsugtig” en gee dit meer CPU-tyd as ander prosesse met hoër nice-waardes.
2. **Renice:**
   - `renice` is ’n opdrag waarmee jy die nice-waarde van ’n proses wat reeds loop, kan verander. Dit kan gebruik word om die prioriteit van prosesse dinamies aan te pas en hul CPU-tydtoewysing te verhoog of te verlaag op grond van nuwe nice-waardes.
   - Byvoorbeeld, as ’n proses tydelik meer CPU-hulpbronne benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS)-klasse

QoS-klasse is ’n meer moderne benadering tot die hantering van threadprioriteite, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS-klasse stel ontwikkelaars in staat om werk volgens die belangrikheid of dringendheid daarvan in verskillende vlakke te **kategoriseer**. macOS bestuur threadprioritisering outomaties op grond van hierdie QoS-klasse:

1. **User Interactive:**
   - Hierdie klas is vir take wat tans met die gebruiker interaksie het of onmiddellike resultate vereis om ’n goeie gebruikerservaring te bied. Hierdie take kry die hoogste prioriteit sodat die koppelvlak reageer (bv. animasies of gebeurtenishantering).
2. **User Initiated:**
   - Take wat die gebruiker begin en waarvoor onmiddellike resultate verwag word, soos om ’n dokument oop te maak of op ’n knoppie te klik wat berekeninge vereis. Hulle het ’n hoë prioriteit, maar laer as User Interactive.
3. **Utility:**
   - Hierdie take loop lank en vertoon gewoonlik ’n vorderingsaanwyser (bv. die aflaai van lêers of die invoer van data). Hulle het ’n laer prioriteit as take wat deur die gebruiker begin is, en hoef nie onmiddellik klaar te wees nie.
4. **Background:**
   - Hierdie klas is vir take wat op die agtergrond loop en nie vir die gebruiker sigbaar is nie. Dit kan take soos indeksering, sinkronisering of rugsteun insluit. Hulle het die laagste prioriteit en minimale impak op stelselwerkverrigting.

Met QoS-klasse hoef ontwikkelaars nie die presiese prioriteitsgetalle te bestuur nie, maar kan hulle eerder op die aard van die taak fokus; die stelsel optimaliseer dan die CPU-hulpbronne daarvolgens.

Daar is ook verskillende **thread-skeduleringsbeleide** wat ’n stel skeduleringsparameters spesifiseer wat die skeduleerder in ag neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition-aanvalle.

## macOS-prosesmisbruik

macOS bied baie meganismes waarmee **prosesse kan interaksie hê, kommunikeer en data deel**. Hoewel hierdie meganismes noodsaaklik is vir die normale werking van die stelsel, kan aanvallers dit misbruik vir injection, code execution of data access.

### Library Injection

Library Injection is ’n tegniek waar ’n aanvaller ’n proses **dwing om ’n kwaadwillige library te laai**. Sodra dit ingespuit is, loop die library binne die konteks van die teikenproses, wat die aanvaller dieselfde toestemmings en toegang as die proses gee.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking behels die **onderskep van funksie-oproepe** of boodskappe binne sagtewarekode. Deur funksies te hook, kan ’n aanvaller die **gedrag verander** van ’n proses, sensitiewe data waarneem of selfs beheer oor die uitvoeringsvloei verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waarmee afsonderlike prosesse **data deel en uitruil**. Hoewel IPC fundamenteel vir baie wettige toepassings is, kan dit ook misbruik word om proses-isolasie te ondermyn, sensitiewe inligting te lek of ongemagtigde aksies uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-toepassings wat met spesifieke env variables uitgevoer word, kan kwesbaar wees vir process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die flags `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser-aanval** uit te voer, wat dit moontlik maak om toetsaanslae, verkeer en cookies te steel, scripts in bladsye in te spuit...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-lêers **definieer gebruikerskoppelvlak-elemente (UI)** en hul interaksies binne ’n toepassing. Hulle kan egter **willekeurige opdragte uitvoer**, en **Gatekeeper keer nie** dat ’n reeds uitgevoerde toepassing weer uitgevoer word as ’n **NIB-lêer gewysig word**. Daarom kan hulle gebruik word om willekeurige programme willekeurige opdragte te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om JVM-opsies via **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** in te spuit en ’n Java- of native agent te laai voordat die toepassing begin.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** laai aanvaller-JavaScript vooraf via `--require` (lêer) of `--import data:text/javascript,…` (lêerloos, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** laai ’n module in ’n interaktiewe REPL, en **`ELECTRON_RUN_AS_NODE`** aktiveer dit alles weer op Electron-binaries.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om code in .NET-toepassings in te spuit via **`DOTNET_STARTUP_HOOKS`** voor `Main`, of deur die .NET-debugging-funksionaliteit te misbruik wanneer die nodige voorvereistes teenwoordig is.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nie-interaktiewe Bash lees **`BASH_ENV`**; interaktiewe POSIX-shells lees **`ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees konfigurasie onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n beheerde opstartlêer uitvoer voordat die bedoelde opdrag loop. Bash voer ook ’n command substitution uit wat in **`PS4`** geplaas is wanneer xtrace geaktiveer is (bv. deur geërfde **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan beheerde PHP-konfigurasie laai waarvan **`auto_prepend_file`** uitgevoer word voordat die teikenscript loop.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Die selfstandige Lua-interpreter voer code of ’n `@file` uit **`LUA_INIT`** (of die weergawe-spesifieke variant daarvan) uit voordat die teikenscript verwerk word.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** herlei na opstartprofiele wat R-code bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, saam met ’n R-library-pad, kan eerder ’n geïnstalleerde pakket outomaties laai.

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

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** herlei na Octave-opstartscripts.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` is ’n kruisplatform-.NET-app, dus maak verskeie omgewingsveranderlikes uitvoering voor die opdrag moontlik: **`XDG_CONFIG_HOME`** herlei na die profielscripts wat met opstart loop, **`PSModulePath`** kaap die outomatiese laai van modules (’n geplante `.psm1` loop tydens import en kan ingeboude cmdlets oorskadu), en die .NET-veranderlikes **`CORECLR_PROFILER`**/**`COR_PROFILER`** en **`DOTNET_STARTUP_HOOKS`** laai aanvallercode in die proses voordat `Main` loop.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende opsies om ’n Perl-script willekeurige code te laat uitvoer in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om Ruby-omgewingsveranderlikes (**`RUBYOPT`**, **`RUBYLIB`**) te misbruik om willekeurige scripts willekeurige code te laat uitvoer:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die standaardbiblioteek-ketting **`PYTHONWARNINGS`** en **`BROWSER`** kan ’n opdrag uitvoer terwyl warning-filters ontleed word. ’n Lêergebaseerde alternatief plaas `sitecustomize.py` op **`PYTHONPATH`**, sodat normale `site`-initialisering dit invoer voordat die teikenscript loop. **`PYTHONBREAKPOINT`** voer ’n gekose callable/module uit wanneer die code `breakpoint()` bereik. Slegs-interaktiewe veranderlikes soos **`PYTHONSTARTUP`** het ’n beperkter toepaslikheid.

Let daarop dat executables wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes gebruik nie, selfs al loop hulle met ’n ingebedde Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (en sy `EXINIT`-terugvalopsie) word tydens ’n normale opstart as Ex-opdragte uitgevoer. Daarom lei `:!cmd` / `:call system(...)` tot code execution wanneer ’n slagoffer Vim/Neovim met ’n beheerde omgewing oopmaak:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Afsonderlik installeer Homebrew dikwels Python onder `/opt/homebrew`, waar lede van die plaaslike `admin`-groep moontlik die launcher kan vervang. Dit is ’n kaping van ’n skryfbare binary, nie injection via ’n omgewingsveranderlike nie; verifieer eienaarskap en ACL’s voordat jy dit as uitbuitbaar beskou.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n oopbron-toepassing wat op **EndpointSecurity** gebaseer is en process injection opspoor en blokkeer. Dit is ’n goeie verwysing vir watter seine via Endpoint Security waarneembaar is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-omgewingsveranderlikes** tydens process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-oproepe — een proses wat ’n ander proses se task port aanvra, wat ’n voorvereiste is om daarin in te spuit.
- **Electron-debugging-argumente** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron-app in debug mode begin en enigiemand toelaat om daaraan te koppel en code daarin uit te voer.<sup>[[3]](#references)</sup>
- **Skep van symlinks/hardlinks oor privilege-vlakke heen** — die klassieke “plant ’n link as ’n gewone gebruiker en wys dit na ’n bevoorregte ligging”-primitive. Let daarop dat **symlinks opgespoor, maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die bestemming van die link bloot voordat dit geskep word nie.

### Calls made by other processes

In [**hierdie blogplasing**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy lees hoe dit moontlik is om die funksie **`task_name_for_pid`** te gebruik om inligting te kry oor ander **prosesse wat code in ’n proses inspuit**, en daarna inligting oor daardie ander proses te kry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** moet hê as die een waaronder die proses loop, of **root** moet wees, om daardie funksie aan te roep (en dit gee inligting oor die proses terug, nie ’n manier om code in te spuit nie).

## References

- [1] [Shield — opsporing van macOS-process injection in oopbron (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-raamwerk](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Waarom Electron-apps nie jou geheime vertroulik kan stoor nie: --inspect-opsie](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Opsporing van taakwysigings](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
