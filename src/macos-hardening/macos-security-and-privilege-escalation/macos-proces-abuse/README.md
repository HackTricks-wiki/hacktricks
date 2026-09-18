# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

'n Proses is 'n instansie van 'n uitvoerbare lêer wat tans loop, maar prosesse voer nie code uit nie; dit is threads. Daarom is **prosesse slegs houers vir threads wat loop** en verskaf hulle die geheue, descriptors, poorte, permissions...

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat 'n presiese kopie van die huidige proses skep. Die **child process** sou dan gewoonlik **`execve`** aanroep om die nuwe uitvoerbare lêer te laai en dit te laat loop. Daarna is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder enige geheuekoppiering.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een oproep kombineer en flags aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ids terug na werklike ids
- `POSIX_SPAWN_SETPGROUP`: Stel process group-affiliasie
- `POSUX_SPAWN_SETSIGDEF`: Stel signal se verstekgedrag
- `POSIX_SPAWN_SETSIGMASK`: Stel signal mask
- `POSIX_SPAWN_SETEXEC`: Voer in dieselfde proses uit (soos `execve` met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op data-segmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Sluit alle file descriptions by exec(2) by verstek
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bits van die ASLR-skuif

Verder aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die spawned process beheer, en **`posix_spawn_file_actions`**-inskrywings wat file descriptors wysig.

Wanneer 'n proses sterf, stuur dit die **return code aan die parent process** (indien die parent sterf, is die nuwe parent PID 1) met die signal `SIGCHLD`. Die parent moet hierdie waarde kry deur `wait4()` of `waitid()` aan te roep, en totdat dit gebeur, bly die child in 'n zombie-toestand waar dit steeds gelys word, maar nie resources verbruik nie.

### PIDs

PIDs, of process identifiers, identifiseer 'n unieke proses. In XNU is die **PIDs** 64 bits lank, neem hulle monotoon toe en vou hulle **nooit om nie** (om abuses te voorkom).

### Process Groups, Sessions & Coalations

**Prosesse** kan in **groups** geplaas word om dit makliker te maak om hulle te hanteer. Byvoorbeeld, commands in 'n shell script sal in dieselfde process group wees, sodat dit moontlik is om hulle **saam te signal** deur byvoorbeeld kill te gebruik.\
Dit is ook moontlik om **prosesse in sessions te groepeer**. Wanneer 'n proses 'n session begin (`setsid(2)`), word die child processes binne die session geplaas, tensy hulle hul eie session begin.

Coalition is nog 'n manier om prosesse in Darwin te groepeer. Deur by 'n coalition aan te sluit, kry 'n proses toegang tot pool resources, deel dit 'n ledger of word dit deur Jetsam geraak. Coalations het verskillende rolle: Leader, XPC service, Extension.

### Credentials & Personae

Elke proses **hou credentials** wat **sy privileges** in die stelsel identifiseer. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groups kan behoort).\
Dit is ook moontlik om die user- en group-id te verander indien die binary die `setuid/setgid`-bit het.\
Daar is verskeie funksies om **nuwe uids/gids te stel**.

Die syscall **`persona`** verskaf 'n **alternatiewe** stel **credentials**. Deur 'n persona aan te neem, aanvaar dit terselfdertyd sy uid, gid en group memberships. In die [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) is dit moontlik om die struct te vind:
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
## Basiese inligting oor Threads

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX threads (`pthreads`), wat deel is van ’n standaard threading API vir C/C++. Die implementering van pthreads in macOS word gevind in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie library verskaf die nodige funksies om threads te skep en te bestuur.
2. **Creating Threads:** Die `pthread_create()`-funksie word gebruik om nuwe threads te skep. Intern roep hierdie funksie `bsdthread_create()` aan, wat ’n laer-vlak system call is wat spesifiek vir die XNU-kernel is (die kernel waarop macOS gebaseer is). Hierdie system call aanvaar verskeie vlae wat van `pthread_attr` (attributes) afgelei word en wat thread-gedrag spesifiseer, insluitend skeduleringsbeleide en stack-grootte.
- **Default Stack Size:** Die verstek-stack-grootte vir nuwe threads is 512 KB, wat voldoende is vir tipiese bedrywighede, maar via thread attributes aangepas kan word indien meer of minder spasie benodig word.
3. **Thread Initialization:** Die `__pthread_init()`-funksie is van kritieke belang tydens thread-opstelling en gebruik die `env[]`-argument om omgewingsveranderlikes te ontleed wat besonderhede oor die stack se ligging en grootte kan insluit.

#### Thread Termination in macOS

1. **Exiting Threads:** Threads word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n thread toe om netjies uit te tree, die nodige opruiming uit te voer en die thread toe te laat om ’n return value terug te stuur aan enige joiners.
2. **Thread Cleanup:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` opgeroep. Dit hanteer die verwydering van alle geassosieerde thread-strukture. Dit deallokeer Mach thread ports (Mach is die kommunikasie-substelsel in die XNU-kernel) en roep `bsdthread_terminate` aan, ’n syscall wat die kernel-vlak-strukture wat met die thread geassosieer word, verwyder.

#### Synchronization Mechanisms

Om toegang tot gedeelde resources te bestuur en race conditions te vermy, verskaf macOS verskeie synchronization primitives. Dit is noodsaaklik in multi-threading-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standaard-mutex met ’n geheue-voetspoor van 60 bytes (56 bytes vir die mutex en 4 bytes vir die signature).
- **Fast Mutex (Signature: 0x4d55545A):** Soortgelyk aan ’n gewone mutex, maar geoptimaliseer vir vinniger bewerkings, en ook 60 bytes groot.
2. **Condition Variables:**
- Word gebruik om vir sekere toestande te wag om voor te kom, met ’n grootte van 44 bytes (40 bytes plus ’n 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Konfigurasie-attributes vir condition variables, met ’n grootte van 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Verseker dat ’n stuk initialiseringskode slegs een keer uitgevoer word. Die grootte daarvan is 12 bytes.
4. **Read-Write Locks:**
- Laat verskeie readers of een writer op ’n slag toe, wat doeltreffende toegang tot gedeelde data moontlik maak.
- **Read Write Lock (Signature: 0x52574c4b):** 196 bytes groot.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes vir read-write locks, met ’n grootte van 20 bytes.

> [!TIP]
> Die laaste 4 bytes van daardie objekte word gebruik om overflows op te spoor.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** word in die konteks van Mach-O-lêers (die formaat vir executables in macOS) gebruik om veranderlikes te verklaar wat spesifiek vir **elke thread** in ’n multi-threaded toepassing is. Dit verseker dat elke thread sy eie afsonderlike instansie van ’n veranderlike het, wat ’n manier bied om konflikte te vermy en data-integriteit te handhaaf sonder die behoefte aan eksplisiete synchronization mechanisms soos mutexes.

In C en verwante tale kan jy ’n thread-local veranderlike verklaar deur die **`__thread`**-keyword te gebruik. Hier is hoe dit in jou voorbeeld werk:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hierdie snippet definieer `tlv_var` as ’n thread-local veranderlike. Elke thread wat hierdie kode uitvoer, sal sy eie `tlv_var` hê, en veranderinge wat een thread aan `tlv_var` maak, sal nie `tlv_var` in ’n ander thread beïnvloed nie.

In die Mach-O-binêre lêer word die data wat met thread-local veranderlikes verband hou, in spesifieke seksies georganiseer:

- **`__DATA.__thread_vars`**: Hierdie seksie bevat die metadata oor die thread-local veranderlikes, soos hul tipes en initialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie seksie word gebruik vir thread-local veranderlikes wat nie eksplisiet geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir nul-geïnisialiseerde data opsygesit word.

Mach-O voorsien ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local veranderlikes te bestuur wanneer ’n thread afsluit. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local data opruim wanneer ’n thread beëindig.

### Thread-prioriteite

Om thread-prioriteite te verstaan, moet gekyk word na hoe die bedryfstelsel besluit watter threads om te laat loop en wanneer. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke thread toegeken word. In macOS en Unix-agtige stelsels word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS)-klasse.

#### Nice en Renice

1. **Nice:**
- Die `nice`-waarde van ’n proses is ’n getal wat sy prioriteit beïnvloed. Elke proses het ’n nice-waarde wat wissel van -20 (die hoogste prioriteit) tot 19 (die laagste prioriteit). Die verstek-nice-waarde wanneer ’n proses geskep word, is gewoonlik 0.
- ’n Laer nice-waarde (nader aan -20) maak ’n proses meer "selfsugtig", wat dit meer CPU-tyd gee in vergelyking met ander prosesse met hoër nice-waardes.
2. **Renice:**
- `renice` is ’n opdrag wat gebruik word om die nice-waarde van ’n proses wat reeds loop, te verander. Dit kan gebruik word om die prioriteit van prosesse dinamies aan te pas en hul CPU-tydtoewysing te verhoog of te verlaag op grond van nuwe nice-waardes.
- Byvoorbeeld, as ’n proses tydelik meer CPU-hulpbronne benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS)-klasse

QoS-klasse is ’n meer moderne benadering tot die hantering van thread-prioriteite, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS-klasse laat ontwikkelaars toe om werk in verskillende vlakke te **kategoriseer** op grond van die belangrikheid of dringendheid daarvan. macOS bestuur thread-prioritisering outomaties op grond van hierdie QoS-klasse:

1. **User Interactive:**
- Hierdie klas is vir take wat tans met die gebruiker interaksie het of onmiddellike resultate vereis om ’n goeie gebruikerservaring te bied. Hierdie take kry die hoogste prioriteit om die koppelvlak responsief te hou (bv. animasies of gebeurtenishantering).
2. **User Initiated:**
- Take wat deur die gebruiker begin word en waarvan onmiddellike resultate verwag word, soos om ’n dokument oop te maak of ’n knoppie te klik wat berekeninge vereis. Dit het ’n hoë prioriteit, maar is laer as user interactive.
3. **Utility:**
- Hierdie take loop lank en vertoon gewoonlik ’n vorderingsaanwyser (bv. die aflaai van lêers of die invoer van data). Hulle het ’n laer prioriteit as user-initiated-take en hoef nie onmiddellik te voltooi nie.
4. **Background:**
- Hierdie klas is vir take wat in die agtergrond werk en nie vir die gebruiker sigbaar is nie. Dit kan take soos indeksering, sinkronisering of rugsteun insluit. Hulle het die laagste prioriteit en minimale impak op stelselwerkverrigting.

Deur QoS-klasse te gebruik, hoef ontwikkelaars nie die presiese prioriteitsnommers te bestuur nie, maar kan hulle eerder op die aard van die taak fokus, waarna die stelsel die CPU-hulpbronne dienooreenkomstig optimaliseer.

Daarbenewens is daar verskillende **thread-skeduleringsbeleide** wat gebruik word om ’n stel skeduleringsparameters te spesifiseer wat die skeduleerder in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition-aanvalle.

## Misbruik van macOS-prosesse

macOS voorsien baie meganismes vir **prosesse om interaksie te hê, te kommunikeer en data te deel**. Hoewel hierdie meganismes noodsaaklik is vir normale stelselwerking, kan aanvallers dit misbruik vir injection, code execution of data access.

### Library Injection

Library Injection is ’n tegniek waarvolgens ’n aanvaller ’n **proses dwing om ’n kwaadwillige library te laai**. Nadat dit geïnjekteer is, loop die library binne die konteks van die teikenproses, wat die aanvaller dieselfde permissions en access as die proses gee.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking behels die **onderskep van function calls** of boodskappe binne sagtewarekode. Deur functions te hook, kan ’n aanvaller die **gedrag van ’n proses wysig**, sensitiewe data waarneem of selfs beheer oor die execution flow verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waardeur aparte prosesse **data deel en uitruil**. Hoewel IPC fundamenteel is vir baie wettige toepassings, kan dit ook misbruik word om process isolation te ondermyn, sensitiewe inligting te lek of ongemagtigde aksies uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron-toepassings wat met spesifieke env variables uitgevoer word, kan kwesbaar wees vir process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die flags `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser attack** uit te voer, wat dit moontlik maak om key presses en traffic te steel, cookies te steel, scripts in bladsye te inject, ens.:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB-lêers **definieer user interface (UI)-elemente** en hul interaksies binne ’n toepassing. Hulle kan egter **arbitrêre commands uitvoer**, en **Gatekeeper keer nie** dat ’n reeds uitgevoerde toepassing weer uitgevoer word indien ’n **NIB-lêer gewysig** is nie. Daarom kan hulle gebruik word om arbitrêre programme arbitrêre commands te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om JVM-options deur **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** te injecteer en ’n Java- of native agent te laai voordat die toepassing begin.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** preload attacker JavaScript via `--require` (file) of `--import data:text/javascript,…` (fileless, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** laai ’n module in ’n interactive REPL, en **`ELECTRON_RUN_AS_NODE`** heraktiveer dit alles op Electron-binaries.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om code in .NET-toepassings te injecteer deur **`DOTNET_STARTUP_HOOKS`** voor `Main`, of deur die .NET debugging-funksionaliteit te misbruik wanneer die voorvereistes daarvoor teenwoordig is.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Nie-interaktiewe Bash lees **`BASH_ENV`**; interactive POSIX shells lees **`ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees konfigurasie onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n beheerde startup file uitvoer voordat die bedoelde command uitgevoer word. Bash voer ook ’n command substitution uit wat in **`PS4`** geplaas is wanneer xtrace geaktiveer is (bv. geërfde **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan beheerde PHP-konfigurasie laai waarvan **`auto_prepend_file`** voor die teikenscript uitgevoer word.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Die standalone Lua-interpreter voer code of ’n `@file` uit **`LUA_INIT`** (of sy version-specific variant) uit voordat die teikenscript verwerk word.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** herlei startup profiles wat R-code bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, saam met ’n R library path, kan eerder ’n geïnstalleerde package outomaties laai.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** herlei die depot waarvan `config/startup.jl` outomaties uitgevoer word.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** of **`ERL_ZFLAGS`** kan ’n Erlang VM **`-eval`**-expression injecteer sonder dat ’n payload file benodig word; Elixir-workloads begin gewoonlik dieselfde VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** herlei Octave se startup scripts.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` is ’n cross-platform .NET-app, dus bied verskeie environment variables pre-command execution: **`XDG_CONFIG_HOME`** herlei die profile scripts wat tydens startup loop, **`PSModulePath`** kaap module auto-loading (’n geplante `.psm1` loop tydens import en kan ingeboude cmdlets shadow), en die .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`**- en **`DOTNET_STARTUP_HOOKS`**-variables laai attacker code in die proses voordat `Main` uitgevoer word.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende options om ’n Perl-script arbitrêre code te laat uitvoer in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om Ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) te misbruik om arbitrêre scripts arbitrêre code te laat uitvoer:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die **`PYTHONWARNINGS`**- en **`BROWSER`** standard-library chain kan ’n command uitvoer tydens warning-filter parsing. ’n File-backed alternatief plaas `sitecustomize.py` op **`PYTHONPATH`**, sodat normale `site` initialization dit import voordat die teikenscript uitgevoer word. **`PYTHONBREAKPOINT`** voer ’n gekose callable/module uit wanneer die code `breakpoint()` bereik. Interactive-only variables soos **`PYTHONSTARTUP`** het ’n nouer toepaslikheid.

Let daarop dat executables wat met **`pyinstaller`** compiled is, nie hierdie environmental variables sal gebruik nie, selfs al loop hulle met ’n embedded Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (en sy **`EXINIT`**-fallback) word tydens ’n normale startup as Ex-commands uitgevoer, dus lei `:!cmd` / `:call system(...)` tot code execution wanneer ’n slagoffer Vim/Neovim met ’n beheerde environment oopmaak:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Afsonderlik installeer Homebrew gewoonlik Python onder `/opt/homebrew`, waar lede van die plaaslike `admin`-groep moontlik die launcher kan vervang. Dit is ’n writable-binary hijack eerder as environment-variable injection; verifieer ownership en ACLs voordat jy dit as exploitable beskou.


## Opsporing

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n open-source **EndpointSecurity**-gebaseerde toepassing wat process injection opspoor en blokkeer. Dit is ’n goeie verwysing vir watter signals deur Endpoint Security waarneembaar is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** tydens process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`**-calls — een proses wat ’n ander se task port aanvra, wat die voorvereiste is om dit te injecteer.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron-app in debug mode begin en enigiemand toelaat om daaraan te attach en code daarin uit te voer.<sup>[[3]](#references)</sup>
- **Symlink/hardlink creation across privilege levels** — die klassieke "plant ’n link as ’n normale gebruiker en wys dit na ’n bevoorregte ligging"-primitive. Let daarop dat **symlinks gemonitor maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die link-bestemming voor creation bloot nie.

### Calls made by other processes

In [**hierdie blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy vind hoe dit moontlik is om die function **`task_name_for_pid`** te gebruik om inligting te verkry oor ander **prosesse wat code in ’n proses injecteer**, en daarna inligting oor daardie ander proses te verkry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** as die een wat die proses uitvoer, of **root**, moet wees om daardie function aan te roep (en dit gee inligting oor die proses terug, nie ’n manier om code te injecteer nie).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Waarom Electron-apps nie jou secrets confidential kan hou nie: --inspect-option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Opsporing van task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
