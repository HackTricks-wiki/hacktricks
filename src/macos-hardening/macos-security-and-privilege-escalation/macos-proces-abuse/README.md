# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

’n Proses is ’n instansie van ’n uitvoerbare program wat loop; prosesse voer egter nie kode uit nie, maar threads. Daarom is **prosesse bloot houers vir threads wat loop** en verskaf hulle geheue, beskrywings, poorte, toestemmings...

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat ’n presiese kopie van die huidige proses skep. Die **child process** sou dan gewoonlik **`execve`** aanroep om die nuwe uitvoerbare program te laai en uit te voer. Daarna is **`vfork`** bekendgestel om hierdie proses te versnel sonder om geheue te kopieer.\
Toe is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een aanroep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ID's terug na werklike ID's
- `POSIX_SPAWN_SETPGROUP`: Stel prosesgroepverwantskap in
- `POSUX_SPAWN_SETSIGDEF`: Stel die verstekgedrag vir seine in
- `POSIX_SPAWN_SETSIGMASK`: Stel die seindekking in
- `POSIX_SPAWN_SETEXEC`: Voer uit in dieselfde proses (soos `execve` met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano-allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasegmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Maak by verstek alle lêerbeskrywings toe met exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-skuifwaarde

Verder aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die geskepte proses beheer, en **`posix_spawn_file_actions`**-inskrywings wat lêerbeskrywings wysig.

Wanneer ’n proses sterf, stuur dit die **terugkeerkode na die ouerproses** (as die ouerproses gesterf het, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouerproses moet hierdie waarde kry deur `wait4()` of `waitid()` aan te roep. Totdat dit gebeur, bly die child in ’n zombietoestand waarin dit steeds gelys word, maar nie hulpbronne verbruik nie.

### PID's

PID's, oftewel prosesidentifiseerders, identifiseer ’n unieke proses. In XNU is **PID's** **64 bis** lank, neem hulle monotonies toe en **loop hulle nooit oor nie** (om misbruik te voorkom).

### Prosesgroepe, sessies en Coalations

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in ’n shell script sal byvoorbeeld in dieselfde prosesgroep wees, sodat dit moontlik is om **seine gelyktydig aan hulle te stuur**, byvoorbeeld met kill.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer ’n proses ’n sessie begin (`setsid(2)`), word die child-prosesse binne die sessie geplaas, tensy hulle hul eie sessie begin.

Coalition is ’n ander manier om prosesse in Darwin te groepeer. Wanneer ’n proses by ’n coalition aansluit, kan dit toegang tot gedeelde hulpbronpoele kry, ’n grootboek deel of deur Jetsam geraak word. Coalitions het verskillende rolle: Leader, XPC service, Extension.

### Geloofsbriewe en personae

Elke proses het **geloofsbriewe** wat sy **voorregte** in die stelsel **identifiseer**. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander as die binêre lêer die `setuid/setgid`-bit het.\
Daar is verskeie funksies om **nuwe uid's/gid's in te stel**.

Die syscall **`persona`** verskaf ’n **alternatiewe** stel **geloofsbriewe**. Deur ’n persona aan te neem, word die uid, gid en groeplidmaatskappe daarvan **gelyktydig** oorgeneem. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) kan die struct gevind word:

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

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX-drade (`pthreads`), wat deel is van ’n standaard-API vir threading in C/C++. Die implementering van pthreads in macOS is in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie biblioteek verskaf die nodige funksies om drade te skep en te bestuur.
2. **Drade skep:** Die `pthread_create()`-funksie word gebruik om nuwe drade te skep. Intern roep hierdie funksie `bsdthread_create()` aan, ’n laervlak-stelseloproep wat spesifiek vir die XNU-kern (die kern waarop macOS gebaseer is) is. Hierdie stelseloproep neem verskeie vlae wat van `pthread_attr` (eienskappe) afgelei word en die draad se gedrag spesifiseer, insluitend skeduleringsbeleide en stapelgrootte.
   - **Verstekstapelgrootte:** Die verstekstapelgrootte vir nuwe drade is 512 KB. Dit is voldoende vir tipiese bewerkings, maar kan met draadeienskappe aangepas word indien meer of minder ruimte nodig is.
3. **Draadinisialisering:** Die `__pthread_init()`-funksie is noodsaaklik tydens draadopstelling. Dit gebruik die `env[]`-argument om omgewingsveranderlikes te ontleed, wat besonderhede oor die stapel se ligging en grootte kan insluit.

#### Beëindiging van drade in macOS

1. **Drade verlaat:** Drade word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n draad skoon afsluit, die nodige opruiming uitvoer en ’n terugkeerwaarde aan enige drade wat daarop wag, terugstuur.
2. **Draadopruiming:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` uitgevoer. Dit hanteer die verwydering van alle gepaardgaande draadstrukture. Dit deallokeer Mach-draadpoorte (Mach is die kommunikasiesubstelsel in die XNU-kern) en roep `bsdthread_terminate` aan, ’n stelseloproep wat die kernvlakstrukture wat met die draad geassosieer word, verwyder.

#### Sinchronisasiemeganismes

Om toegang tot gedeelde hulpbronne te bestuur en resiestoestande te vermy, bied macOS verskeie sinchronisasieprimitiewe. Dit is noodsaaklik in multithreading-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexe:**
   - **Gewone mutex (handtekening: 0x4D555458):** Standaardmutex met ’n geheuevoetspoor van 60 grepe (56 grepe vir die mutex en 4 grepe vir die handtekening).
   - **Vinnige mutex (handtekening: 0x4d55545A):** Soortgelyk aan ’n gewone mutex, maar geoptimaliseer vir vinniger bewerkings; dit is ook 60 grepe groot.
2. **Toestandsveranderlikes:**
   - Word gebruik om op sekere toestande te wag; hulle is 44 grepe groot (40 grepe plus ’n 4-greep-handtekening).
   - **Toestandsveranderlike-eienskappe (handtekening: 0x434e4441):** Konfigurasie-eienskappe vir toestandsveranderlikes, 12 grepe groot.
3. **Eenmalige veranderlike (handtekening: 0x4f4e4345):**
   - Verseker dat ’n stuk inisialiseringskode slegs een keer uitgevoer word. Dit is 12 grepe groot.
4. **Lees-skryf-slotte:**
   - Laat verskeie lesers of een skrywer op ’n slag toe, wat doeltreffende toegang tot gedeelde data moontlik maak.
   - **Lees-skryf-slot (handtekening: 0x52574c4b):** 196 grepe groot.
   - **Lees-skryf-slot-eienskappe (handtekening: 0x52574c41):** Eienskappe vir lees-skryf-slotte, 20 grepe groot.

> [!TIP]
> Die laaste 4 grepe van hierdie objekte word gebruik om oorlope op te spoor.

### Draadplaaslike veranderlikes (TLV)

**Draadplaaslike veranderlikes (TLV)** word in die konteks van Mach-O-lêers (die formaat vir uitvoerbare lêers in macOS) gebruik om veranderlikes te verklaar wat in ’n multithreading-toepassing spesifiek vir **elke draad** is. Dit verseker dat elke draad sy eie afsonderlike instansie van ’n veranderlike het, en bied ’n manier om konflikte te vermy en data-integriteit te handhaaf sonder die behoefte aan uitdruklike sinchronisasiemeganismes soos mutexe.

In C en verwante tale kan jy ’n draadplaaslike veranderlike met die sleutelwoord **`__thread`** verklaar. Só werk dit in jou voorbeeld:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Hierdie snippet definieer `tlv_var` as ’n thread-local-veranderlike. Elke thread wat hierdie kode uitvoer, het sy eie `tlv_var`, en veranderinge wat een thread aan `tlv_var` maak, beïnvloed nie `tlv_var` in ’n ander thread nie.

In die Mach-O-binêre lêer word data wat met thread-local-veranderlikes verband hou, in spesifieke afdelings georganiseer:

- **`__DATA.__thread_vars`**: Hierdie afdeling bevat metadata oor die thread-local-veranderlikes, soos hul tipes en inisialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie afdeling word gebruik vir thread-local-veranderlikes wat nie eksplisiet geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir nul-geïnisialiseerde data opsygesit is.

Mach-O bied ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local-veranderlikes te bestuur wanneer ’n thread beëindig. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local-data opruim wanneer ’n thread beëindig word.

### Thread-prioriteite

Om thread-prioriteite te verstaan, moet jy kyk na hoe die bedryfstelsel besluit watter threads uitgevoer word en wanneer. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke thread toegeken word. In macOS en Unix-agtige stelsels word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS)-klasse.

#### Nice en Renice

1. **Nice:**
   - Die `nice`-waarde van ’n proses is ’n getal wat sy prioriteit beïnvloed. Elke proses het ’n nice-waarde van -20 (die hoogste prioriteit) tot 19 (die laagste prioriteit). Die verstek-nice-waarde wanneer ’n proses geskep word, is gewoonlik 0.
   - ’n Laer nice-waarde (nader aan -20) maak ’n proses meer “selfsugtig” en gee dit meer CPU-tyd as ander prosesse met hoër nice-waardes.
2. **Renice:**
   - `renice` is ’n opdrag waarmee jy die nice-waarde van ’n proses wat reeds loop, kan verander. Dit kan gebruik word om die prioriteit van prosesse dinamies aan te pas en hul CPU-tydtoekenning te verhoog of te verlaag op grond van nuwe nice-waardes.
   - As ’n proses byvoorbeeld tydelik meer CPU-hulpbronne nodig het, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS)-klasse

QoS-klasse is ’n meer moderne benadering tot die hantering van thread-prioriteite, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS-klasse laat ontwikkelaars toe om werk volgens die belangrikheid of dringendheid daarvan in verskillende vlakke te **kategoriseer**. macOS bestuur thread-prioritisering outomaties op grond van hierdie QoS-klasse:

1. **User Interactive:**
   - Hierdie klas is vir take wat tans met die gebruiker interaksie het of onmiddellike resultate vereis om ’n goeie gebruikerservaring te bied. Hierdie take kry die hoogste prioriteit om die koppelvlak responsief te hou (bv. animasies of gebeurtenishantering).
2. **User Initiated:**
   - Take wat die gebruiker begin en waarvoor onmiddellike resultate verwag word, soos om ’n dokument oop te maak of op ’n knoppie te klik wat berekeninge vereis. Dit het hoë prioriteit, maar laer as user interactive.
3. **Utility:**
   - Hierdie take duur lank en wys gewoonlik ’n vorderingsaanwyser (bv. lêers aflaai of data invoer). Hulle het laer prioriteit as take wat deur die gebruiker begin is, en hoef nie onmiddellik klaar te wees nie.
4. **Background:**
   - Hierdie klas is vir take wat in die agtergrond loop en nie vir die gebruiker sigbaar is nie. Voorbeelde sluit in indeksering, sinkronisering of rugsteun. Hulle het die laagste prioriteit en minimale impak op stelselwerkverrigting.

Met QoS-klasse hoef ontwikkelaars nie die presiese prioriteitsgetalle te bestuur nie; hulle kan eerder op die aard van die taak fokus, en die stelsel optimaliseer die CPU-hulpbronne dienooreenkomstig.

Daar is ook verskillende **thread-skeduleringsbeleide** wat ’n stel skeduleringsparameters spesifiseer wat die skeduleerder in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition-aanvalle.

## macOS-prosesmisbruik

macOS bied baie meganismes waarmee **prosesse met mekaar kan interaksie hê, kommunikeer en data deel**. Hoewel hierdie meganismes noodsaaklik is vir normale stelselwerking, kan aanvallers dit misbruik vir injection, kode-uitvoering of toegang tot data.

### Library Injection

Library Injection is ’n tegniek waar ’n aanvaller **’n proses dwing om ’n kwaadwillige library te laai**. Sodra dit ingevoeg is, loop die library binne die konteks van die teikenproses, wat die aanvaller dieselfde toestemmings en toegang as die proses gee.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking behels die **onderskep van funksie-oproepe** of boodskappe binne sagtewarekode. Deur funksies te hook, kan ’n aanvaller die **gedrag van ’n proses verander**, sensitiewe data waarneem of selfs beheer oor die uitvoeringsvloei verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Hierdie bladsy bespreek ARM64 unwind-metadata, arm64e PAC-beperkings en sintetiese oproepkettings.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waarmee afsonderlike prosesse **data deel en uitruil**. Hoewel IPC fundamenteel is vir baie wettige toepassings, kan dit ook misbruik word om proses-isolasie te ondermyn, sensitiewe inligting te lek of ongemagtigde aksies uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-toepassings wat met spesifieke omgewingsveranderlikes uitgevoer word, kan kwesbaar wees vir proses-injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die vlae `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man-in-the-browser-aanval** uit te voer waarmee toetsaanslae, verkeer en koekies gesteel en scripts in bladsye ingevoeg kan word...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-lêers **definieer gebruikerskoppelvlak (UI)-elemente** en hul interaksies binne ’n toepassing. Hulle kan egter **willekeurige opdragte uitvoer**, en **Gatekeeper keer nie dat ’n reeds uitgevoerde toepassing weer uitgevoer word** as ’n **NIB-lêer gewysig is nie**. Daarom kan hulle gebruik word om willekeurige programme willekeurige opdragte te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om JVM-opsies deur **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** in te voeg en ’n Java- of native agent te laai voordat die toepassing begin.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** laai aanvaller-JavaScript vooraf via `--require` (lêer) of `--import data:text/javascript,…` (sonder lêer, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** laai ’n module in ’n interaktiewe REPL, en **`ELECTRON_RUN_AS_NODE`** aktiveer dit alles weer op Electron-binêre lêers.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om kode in .NET-toepassings in te voeg via **`DOTNET_STARTUP_HOOKS`** voor `Main`, of deur die .NET-ontfoutingsfunksionaliteit te misbruik wanneer die nodige voorvereistes teenwoordig is.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nie-interaktiewe Bash lees **`BASH_ENV`**; interaktiewe POSIX-shells lees **`ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees konfigurasie onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n beheerde opstartlêer uitvoer voordat die beoogde opdrag loop. Bash voer ook ’n command substitution in **`PS4`** uit wanneer xtrace geaktiveer is (bv. deur oorgeërfde **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan beheerde PHP-konfigurasie laai waarvan **`auto_prepend_file`** uitgevoer word voordat die teikenscript loop.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Die selfstandige Lua-tolk voer kode of ’n `@file` uit **`LUA_INIT`** (of die weergawe-spesifieke variant daarvan) uit voordat die teikenscript verwerk word.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** herlei opstartprofiele wat R-kode bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** plus ’n R-library-pad kan eerder ’n geïnstalleerde pakket outomaties laai.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** herlei die depot waarvan `config/startup.jl` outomaties uitgevoer word.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** of **`ERL_ZFLAGS`** kan ’n Erlang VM **`-eval`**-uitdrukking invoeg sonder dat ’n payload-lêer nodig is; Elixir-werkladings begin gewoonlik dieselfde VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** herlei Octave-opstartscripts.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` is ’n kruisplatform-.NET-toepassing, dus kan verskeie omgewingsveranderlikes uitvoering voor die opdrag moontlik maak: **`XDG_CONFIG_HOME`** herlei die profielscripts wat tydens opstart loop, **`PSModulePath`** kaap outomatiese modulelaaiing (’n geplante `.psm1` loop tydens invoer en kan ingeboude cmdlets oorskadu), en die .NET-veranderlikes **`CORECLR_PROFILER`**/**`COR_PROFILER`** en **`DOTNET_STARTUP_HOOKS`** laai aanvallerskode in die proses voordat `Main` loop.

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


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die standaardbiblioteekketting met **`PYTHONWARNINGS`** en **`BROWSER`** kan ’n opdrag uitvoer tydens die ontleding van waarskuwingsfilters. ’n Alternatief wat ’n lêer gebruik, plaas `sitecustomize.py` op **`PYTHONPATH`**, sodat normale `site`-inisialisering dit invoer voordat die teikenscript loop. **`PYTHONBREAKPOINT`** voer ’n gekose callable/module uit wanneer die kode `breakpoint()` bereik. Veranderlikes wat slegs vir interaktiewe gebruik bedoel is, soos **`PYTHONSTARTUP`**, het ’n beperkter toepassingsgebied.

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes gebruik nie, selfs wanneer hulle met ’n ingebedde Python uitgevoer word.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (en die terugvalopsie `EXINIT`) word tydens normale opstart as Ex-opdragte uitgevoer. Dus lei `:!cmd` / `:call system(...)` tot kode-uitvoering wanneer ’n slagoffer Vim/Neovim met ’n beheerde omgewing oopmaak:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Homebrew installeer Python dikwels onder `/opt/homebrew`, waar lede van die plaaslike `admin`-groep moontlik die launcher kan vervang. Dit is ’n kaping van ’n skryfbare binêre lêer, nie injection via omgewingsveranderlikes nie; verifieer eienaarskap en ACL’s voordat jy dit as uitbuitbaar beskou.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n oopbron-toepassing gebaseer op **EndpointSecurity** wat proses-injection opspoor en blokkeer. Dit is ’n goeie verwysing vir seine wat via Endpoint Security waarneembaar is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection-omgewingsveranderlikes** tydens prosesuitvoering: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-oproepe — wanneer een proses ’n ander se task port aanvra, wat ’n voorvereiste is om daarin te inject.
- **Electron-ontfoutingsargumente** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron-toepassing in ontfoutingsmodus begin en enigiemand toelaat om daaraan te koppel en kode daarin uit te voer.<sup>[[3]](#references)</sup>
- **Skep van simboliese/harde skakels oor voorregvlakke heen** — die klassieke beginsel van “plant ’n skakel as ’n gewone gebruiker en laat dit na ’n bevoorregte ligging wys”. Let daarop dat **simboliese skakels opgespoor, maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die skakelbestemming beskikbaar voordat dit geskep is nie.

### Oproepe deur ander prosesse

In [**hierdie blogplasing**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy lees hoe dit moontlik is om die funksie **`task_name_for_pid`** te gebruik om inligting te kry oor ander **prosesse wat kode in ’n proses inject**, en dan inligting oor daardie ander proses te kry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** as die een wat die proses uitvoer, of **root**, moet wees om daardie funksie aan te roep (en dit gee inligting oor die proses terug, nie ’n manier om kode te inject nie).

## References

- [1] [Shield — oopbron-opsporing van macOS-proses-injection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity-raamwerk](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Waarom Electron-toepassings nie jou geheime vertroulik kan hou nie: --inspect-opsie](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Opsporing van taakwysigings](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
