# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Basiese prosesinligting

'n Process is 'n instansie van 'n uitvoerbare program wat tans loop; prosesse voer egter nie kode uit nie—threads doen dit. Daarom is **prosesse bloot houers vir threads wat loop**, wat die geheue, descriptors, poorte, permissions...

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat 'n presiese kopie van die huidige proses geskep het. Daarna sou die **child process** gewoonlik **`execve`** aanroep om die nuwe uitvoerbare program te laai en dit uit te voer. Vervolgens is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder enige geheuek opiëer.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een oproep kombineer en flags aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ids terug na werklike ids
- `POSIX_SPAWN_SETPGROUP`: Stel process group-affiliasie
- `POSUX_SPAWN_SETSIGDEF`: Stel signal se verstekgedrag
- `POSIX_SPAWN_SETSIGMASK`: Stel signal mask
- `POSIX_SPAWN_SETEXEC`: Voer in dieselfde proses uit (soos `execve` met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin suspended
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op data-segmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Sluit alle file descriptions by exec(2) by verstek
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bits van die ASLR-skuif

Daarbenewens aanvaar `posix_spawn` **`posix_spawnattr`**-instellings wat aspekte van die spawned process beheer, asook **`posix_spawn_file_actions`**-inskrywings wat file descriptors wysig.

Wanneer 'n proses sterf, stuur dit die **return code aan die parent process** (indien die parent gesterf het, is die nuwe parent PID 1) met die signal `SIGCHLD`. Die parent moet hierdie waarde verkry deur `wait4()` of `waitid()` aan te roep. Totdat dit gebeur, bly die child in 'n zombie state waarin dit steeds gelys word, maar nie hulpbronne verbruik nie.

### PIDs

PIDs, oftewel process identifiers, identifiseer 'n unieke proses. In XNU is die **PIDs** 64 bits lank, neem hulle monotoon toe en **wikkel hulle nooit om nie** (om misbruik te voorkom).

### Process Groups, Sessions & Coalitions

**Prosesse** kan in **groups** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in 'n shell script sal byvoorbeeld in dieselfde process group wees, sodat dit moontlik is om **hulle saam te signal** deur byvoorbeeld kill te gebruik.\
Dit is ook moontlik om **prosesse in sessions te groepeer**. Wanneer 'n proses 'n session begin (`setsid(2)`), word die child processes binne die session geplaas, tensy hulle hul eie session begin.

Coalition is nog 'n manier om prosesse in Darwin te groepeer. Deur by 'n coalition aan te sluit, kan 'n proses toegang tot pool-hulpbronne verkry, 'n ledger deel of deur Jetsam geraak word. Coalitions het verskillende rolle: Leader, XPC service, Extension.

### Credentials & Personae

Elke proses **hou credentials** wat sy **permissions** in die stelsel **identifiseer**. Elke proses het een primêre `uid` en een primêre `gid` (hoewel dit aan verskeie groups kan behoort).\
Dit is ook moontlik om die user- en group-id te verander indien die binary die **`setuid/setgid`**-bit het.\
Daar is verskeie funksies om **nuwe uids/gids te stel**.

Die syscall **`persona`** verskaf 'n **alternatiewe** stel **credentials**. Deur 'n persona aan te neem, aanvaar die proses terselfdertyd sy uid, gid en group memberships. In die [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) is dit moontlik om die struct te vind:
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

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX threads (`pthreads`), wat deel is van ’n standaard threading API vir C/C++. Die implementering van pthreads in macOS word gevind in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie biblioteek verskaf die nodige funksies om threads te skep en te bestuur.
2. **Skep van Threads:** Die `pthread_create()`-funksie word gebruik om nuwe threads te skep. Intern roep hierdie funksie `bsdthread_create()` aan, wat ’n laer-vlak system call is wat spesifiek is vir die XNU-kernel (die kernel waarop macOS gebaseer is). Hierdie system call neem verskeie flags wat van `pthread_attr` (attribute) afgelei word en wat thread-gedrag spesifiseer, insluitend skeduleringsbeleide en stack-grootte.
- **Verstek Stack-grootte:** Die verstek stack-grootte vir nuwe threads is 512 KB, wat voldoende is vir tipiese bewerkings, maar via thread attributes aangepas kan word indien meer of minder spasie nodig is.
3. **Thread-inisialisering:** Die `__pthread_init()`-funksie is belangrik tydens thread-opstelling en gebruik die `env[]`-argument om omgewingsveranderlikes te ontleed wat besonderhede oor die stack se ligging en grootte kan bevat.

#### Thread-terminering in macOS

1. **Verlaat van Threads:** Threads word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie stel ’n thread in staat om netjies te exit, die nodige cleanup uit te voer en die thread toe te laat om ’n return value terug te stuur na enige joiners.
2. **Thread-cleanup:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` opgeroep, wat die verwydering van alle geassosieerde thread-strukture hanteer. Dit deallokeer Mach thread ports (Mach is die kommunikasiesubstelsel in die XNU-kernel) en roep `bsdthread_terminate` aan, ’n syscall wat die kernel-vlak-strukture wat met die thread geassosieer word, verwyder.

#### Synchronization-meganismes

Om toegang tot shared resources te bestuur en race conditions te vermy, verskaf macOS verskeie synchronization primitives. Dit is noodsaaklik in multi-threading-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standaard mutex met ’n memory footprint van 60 bytes (56 bytes vir die mutex en 4 bytes vir die signature).
- **Fast Mutex (Signature: 0x4d55545A):** Soortgelyk aan ’n regular mutex, maar geoptimaliseer vir vinniger bewerkings, en ook 60 bytes groot.
2. **Condition Variables:**
- Word gebruik om te wag vir sekere conditions om voor te kom, met ’n grootte van 44 bytes (40 bytes plus ’n 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes vir condition variables, met ’n grootte van 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Verseker dat ’n stuk initialization code slegs een keer uitgevoer word. Die grootte daarvan is 12 bytes.
4. **Read-Write Locks:**
- Laat veelvuldige readers of een writer op ’n slag toe, wat doeltreffende toegang tot shared data moontlik maak.
- **Read Write Lock (Signature: 0x52574c4b):** Het ’n grootte van 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes vir read-write locks, met ’n grootte van 20 bytes.

> [!TIP]
> Die laaste 4 bytes van daardie objects word gebruik om overflows op te spoor.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** in die konteks van Mach-O-lêers (die formaat vir executables in macOS) word gebruik om veranderlikes te declareer wat spesifiek is vir **elke thread** in ’n multi-threaded toepassing. Dit verseker dat elke thread sy eie aparte instance van ’n veranderlike het, wat ’n manier bied om conflicts te vermy en data-integriteit te handhaaf sonder dat eksplisiete synchronization mechanisms soos mutexes nodig is.

In C en verwante tale kan jy ’n thread-local variable declareer deur die **`__thread`**-keyword te gebruik. Hier is hoe dit in jou voorbeeld werk:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hierdie snippet definieer `tlv_var` as ’n thread-local variable. Elke thread wat hierdie code uitvoer, sal sy eie `tlv_var` hê, en veranderinge wat een thread aan `tlv_var` maak, sal nie `tlv_var` in ’n ander thread beïnvloed nie.

In die Mach-O binary word die data wat met thread-local variables verband hou, in spesifieke sections georganiseer:

- **`__DATA.__thread_vars`**: Hierdie section bevat die metadata oor die thread-local variables, soos hul tipes en initialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie section word gebruik vir thread-local variables wat nie eksplisiet geïnitialiseer is nie. Dit is ’n gedeelte van die memory wat vir zero-initialized data gereserveer is.

Mach-O verskaf ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local variables te bestuur wanneer ’n thread exit. Hierdie API laat jou toe om **destructors te registreer**—spesiale functions wat thread-local data opruim wanneer ’n thread terminateer.

### Threading Priorities

Om thread priorities te verstaan, behels dat daar gekyk word na hoe die operating system besluit watter threads om te run en wanneer. Hierdie besluit word beïnvloed deur die priority level wat aan elke thread toegeken is. In macOS en Unix-like systems word dit hanteer met concepts soos `nice`, `renice` en Quality of Service (QoS) classes.

#### Nice en Renice

1. **Nice:**
- Die `nice` value van ’n process is ’n getal wat sy priority beïnvloed. Elke process het ’n nice value wat van -20 (die hoogste priority) tot 19 (die laagste priority) strek. Die default nice value wanneer ’n process geskep word, is gewoonlik 0.
- ’n Laer nice value (nader aan -20) maak ’n process meer “selfish” en gee dit meer CPU time in vergelyking met ander processes met hoër nice values.
2. **Renice:**
- `renice` is ’n command wat gebruik word om die nice value van ’n reeds running process te verander. Dit kan gebruik word om die priority van processes dinamies aan te pas en hul CPU time allocation te verhoog of te verlaag op grond van nuwe nice values.
- Byvoorbeeld, indien ’n process tydelik meer CPU resources benodig, kan jy sy nice value met `renice` verlaag.

#### Quality of Service (QoS) Classes

QoS classes is ’n meer moderne benadering tot die hantering van thread priorities, veral in systems soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS classes laat developers toe om werk in verskillende levels te **kategoriseer** op grond van die belangrikheid of dringendheid daarvan. macOS bestuur thread prioritization outomaties op grond van hierdie QoS classes:

1. **User Interactive:**
- Hierdie class is vir tasks wat tans met die user interaksie het of immediate results benodig om ’n goeie user experience te verskaf. Hierdie tasks kry die hoogste priority om die interface responsive te hou (byvoorbeeld animations of event handling).
2. **User Initiated:**
- Tasks wat deur die user geïnisieer word en waarvan immediate results verwag word, soos om ’n document oop te maak of op ’n button te click wat computations vereis. Dit is ’n hoë priority, maar laer as user interactive.
3. **Utility:**
- Hierdie tasks loop lank en wys gewoonlik ’n progress indicator (byvoorbeeld wanneer files afgelaai of data geïmporteer word). Hulle het ’n laer priority as user-initiated tasks en hoef nie onmiddellik te voltooi nie.
4. **Background:**
- Hierdie class is vir tasks wat in die background loop en nie vir die user sigbaar is nie. Dit kan tasks soos indexing, syncing of backups insluit. Hulle het die laagste priority en ’n minimale impak op system performance.

Deur QoS classes te gebruik, hoef developers nie die presiese priority numbers te bestuur nie, maar kan hulle eerder op die aard van die task fokus, waarna die system die CPU resources dienooreenkomstig optimaliseer.

Daarbenewens is daar verskillende **thread scheduling policies** wat gebruik word om ’n stel scheduling parameters te spesifiseer wat die scheduler in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition attacks.

## macOS Process Abuse

macOS verskaf baie mechanisms vir **processes om interaksie te hê, te kommunikeer en data te deel**. Hoewel hierdie mechanisms noodsaaklik is vir normale system operation, kan attackers dit abuse vir injection, code execution of data access.

### Library Injection

Library Injection is ’n technique waarin ’n attacker ’n process **force om ’n malicious library te load**. Nadat dit injected is, loop die library binne die context van die target process en gee dit die attacker dieselfde permissions en access as die process.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking behels die **intercept van function calls** of messages binne software code. Deur functions te hook, kan ’n attacker die **behavior van ’n process modify**, sensitive data observeer of selfs control oor die execution flow verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende methods waardeur aparte processes **data share en exchange**. Hoewel IPC fundamenteel vir baie legitimate applications is, kan dit ook misbruik word om process isolation te ondermyn, sensitive information te leak of unauthorized actions uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications wat met spesifieke env variables uitgevoer word, kan kwesbaar wees vir process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die flags `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser attack** uit te voer, wat dit moontlik maak om keystrokes en traffic te steal, cookies te steal, scripts in pages te inject, ensovoorts:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **definieer user interface (UI)-elements** en hul interactions binne ’n application. Hulle kan egter **arbitrary commands execute**, en **Gatekeeper keer nie dat** ’n reeds executed application weer executed word indien ’n **NIB file modified** is nie. Daarom kan hulle gebruik word om arbitrary programs arbitrary commands te laat execute:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om JVM options deur **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** of **`JDK_JAVA_OPTIONS`** te inject en ’n Java- of native agent te load voordat die application start.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om code in .NET applications te inject deur **`DOTNET_STARTUP_HOOKS`** voor `Main`, of deur die .NET debugging functionality te abuse wanneer die prerequisites daarvoor teenwoordig is.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash lees **`BASH_ENV`**; zsh lees **`$ZDOTDIR/.zshenv`**; en fish lees configuration onder **`XDG_CONFIG_HOME`** of **`XDG_DATA_DIRS`**. Elkeen kan ’n controlled startup file execute voordat die intended command uitgevoer word:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** of **`PHP_INI_SCAN_DIR`** kan controlled PHP configuration load waarvan **`auto_prepend_file`** voor die target script execute.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Die standalone Lua interpreter execute code of ’n `@file` vanaf **`LUA_INIT`** (of sy version-specific variant) voordat die target script verwerk word.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** en **`R_PROFILE`** redirect startup profiles wat R code bevat. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, saam met ’n R library path, kan eerder ’n geïnstalleerde package outomaties load.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redirect die depot waarvan `config/startup.jl` outomaties executed word.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** of **`ERL_ZFLAGS`** kan ’n Erlang VM **`-eval`** expression inject sonder dat ’n payload file vereis word; Elixir workloads start gewoonlik dieselfde VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** en **`OCTAVE_VERSION_INITFILE`** redirect Octave startup scripts.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

Op macOS en Linux kan **`XDG_CONFIG_HOME`** PowerShell user profiles redirect wat execute wanneer `pwsh` start.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende options om ’n Perl script arbitrary code te laat execute in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om Ruby env variables te abuse sodat arbitrary scripts arbitrary code execute:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Die **`PYTHONWARNINGS`** en **`BROWSER`** standard-library chain kan ’n command execute tydens warning-filter parsing. ’n File-backed alternatief plaas `sitecustomize.py` op **`PYTHONPATH`**, sodat normale `site` initialization dit import voordat die target script uitgevoer word. Interactive-only variables soos **`PYTHONSTARTUP`** het ’n meer beperkte toepaslikheid.

Let daarop dat executables wat met **`pyinstaller`** compiled is, nie hierdie environmental variables sal gebruik nie, selfs al loop hulle met ’n embedded Python.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

Afsonderlik installeer Homebrew gewoonlik Python onder `/opt/homebrew`, waar members van die plaaslike `admin` group moontlik die launcher kan replace. Dit is ’n writable-binary hijack eerder as environment-variable injection; verifieer ownership en ACLs voordat jy dit as exploitable beskou.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n open-source **EndpointSecurity**-based application wat process injection detecteer en block. Dit is ’n goeie reference vir watter signals deur Endpoint Security observable is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Injection environment variables** op process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** calls — een process wat vir ’n ander process se task port vra, wat die prerequisite is om daarin te inject.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron app in debug mode start en enigiemand toelaat om daaraan te attach en code daarin te run.<sup>[[3]](#references)</sup>
- **Symlink/hardlink creation across privilege levels** — die klassieke “plant ’n link as ’n normal user en wys dit na ’n privileged location”-primitive. Let daarop dat **symlinks op gealert kan word maar nie geblock kan word nie**: EndpointSecurity stel nie die link destination voor creation bloot nie.

### Calls made by other processes

In [**hierdie blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy uitvind hoe dit moontlik is om die function **`task_name_for_pid`** te gebruik om information te kry oor ander **processes wat code in ’n process inject**, en dan information oor daardie ander process te kry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** as die een wat die process run, of **root**, moet wees om daardie function te call (en dit gee information oor die process terug, nie ’n manier om code te inject nie).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
