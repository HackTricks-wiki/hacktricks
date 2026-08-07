# Prosesmisbruik in macOS

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

'n Proses is 'n instansie van 'n uitvoerbare lêer wat tans loop; prosesse voer egter nie kode uit nie, maar threads. Daarom is **prosesse bloot houers vir lopende threads** wat die geheue, descriptors, poorte, permissions en meer verskaf.

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat 'n presiese kopie van die huidige proses skep. Die **child process** sou dan gewoonlik **`execve`** aanroep om die nuwe uitvoerbare lêer te laai en dit uit te voer. Daarna is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder enige geheuekopiëring.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een oproep kombineer en flags aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ids terug na werklike ids
- `POSIX_SPAWN_SETPGROUP`: Stel process group-affiliasie in
- `POSUX_SPAWN_SETSIGDEF`: Stel signal se verstekgedrag in
- `POSIX_SPAWN_SETSIGMASK`: Stel signal mask in
- `POSIX_SPAWN_SETEXEC`: Voer in dieselfde proses uit (soos `execve` met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin suspended
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op data-segmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Maak alle file descriptions by verstek toe op exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bits van die ASLR-slide

Verder laat `posix_spawn` toe dat 'n array van **`posix_spawnattr`** gespesifiseer word wat sekere aspekte van die spawned process beheer, asook **`posix_spawn_file_actions`** om die toestand van die descriptors te wysig.

Wanneer 'n proses beëindig word, stuur dit die **return code aan die parent process** (indien die parent beëindig is, is die nuwe parent PID 1) met die signal `SIGCHLD`. Die parent moet hierdie waarde verkry deur `wait4()` of `waitid()` aan te roep. Totdat dit gebeur, bly die child in 'n zombie state waarin dit steeds gelys word, maar nie resources verbruik nie.

### PIDs

PIDs, process identifiers, identifiseer 'n unieke proses. In XNU is die **PIDs** 64 bits lank, neem dit monotonies toe en **wrap dit nooit om nie** (om misbruik te voorkom).

### Process Groups, Sessions & Coalations

**Prosesse** kan in **groups** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in 'n shell script sal byvoorbeeld in dieselfde process group wees, sodat dit moontlik is om hulle **saam te signal** deur byvoorbeeld kill te gebruik.\
Dit is ook moontlik om **prosesse in sessions** te groepeer. Wanneer 'n proses 'n session begin (`setsid(2)`), word die child processes binne die session geplaas, tensy hulle hul eie session begin.

Coalition is nog 'n manier om prosesse in Darwin te groepeer. Deur by 'n coalition aan te sluit, kry 'n proses toegang tot pool resources, deel dit 'n ledger, of word dit aan Jetsam blootgestel. Coalitions het verskillende rolle: Leader, XPC service, Extension.

### Credentials & Personae

Elke proses hou **credentials** wat sy **privileges identifiseer** in die stelsel. Elke proses sal een primêre `uid` en een primêre `gid` hê (hoewel dit aan verskeie groups kan behoort).\
Dit is ook moontlik om die user- en group-id te verander indien die binary die `setuid/setgid`-bit het.\
Daar is verskeie funksies om **nuwe uids/gids te stel**.

Die syscall **`persona`** verskaf 'n **alternatiewe** stel **credentials**. Deur 'n persona aan te neem, neem dit sy uid, gid en group memberships **tegelyk** aan. In die [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) is dit moontlik om die struct te vind:
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

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX threads (`pthreads`), wat deel is van ’n standaard threading-API vir C/C++. Die implementering van pthreads in macOS word gevind in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie library verskaf die nodige funksies om threads te skep en te bestuur.
2. **Creating Threads:** Die `pthread_create()`-funksie word gebruik om nuwe threads te skep. Intern roep hierdie funksie `bsdthread_create()` aan, wat ’n laervlak-stelseloproep is wat spesifiek is vir die XNU-kernel (die kernel waarop macOS gebaseer is). Hierdie stelseloproep aanvaar verskeie flags wat van `pthread_attr` (attributes) afgelei word en wat thread-gedrag spesifiseer, insluitend scheduling policies en stack-grootte.
- **Default Stack Size:** Die verstek-stack-grootte vir nuwe threads is 512 KB, wat voldoende is vir tipiese bewerkings, maar via thread attributes aangepas kan word indien meer of minder ruimte benodig word.
3. **Thread Initialization:** Die `__pthread_init()`-funksie is noodsaaklik tydens thread-opstelling en gebruik die `env[]`-argument om environment variables te ontleed wat besonderhede oor die stack se ligging en grootte kan bevat.

#### Thread Termination in macOS

1. **Exiting Threads:** Threads word tipies beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n thread toe om netjies uit te tree, die nodige cleanup uit te voer en ’n return value terug te stuur na enige joiners.
2. **Thread Cleanup:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` opgeroep. Dit hanteer die verwydering van alle geassosieerde thread-strukture. Dit deallokeer Mach thread ports (Mach is die kommunikasiesubstelsel in die XNU-kernel) en roep `bsdthread_terminate` aan, ’n syscall wat die kernel-vlak-strukture wat met die thread geassosieer word, verwyder.

#### Synchronization Mechanisms

Om toegang tot shared resources te bestuur en race conditions te voorkom, verskaf macOS verskeie synchronization primitives. Dit is krities in multi-threading-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standaard-mutex met ’n memory footprint van 60 bytes (56 bytes vir die mutex en 4 bytes vir die signature).
- **Fast Mutex (Signature: 0x4d55545A):** Soortgelyk aan ’n regular mutex, maar geoptimaliseer vir vinniger bewerkings, en ook 60 bytes groot.
2. **Condition Variables:**
- Word gebruik om vir sekere toestande te wag om voor te kom, met ’n grootte van 44 bytes (40 bytes plus ’n 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes vir condition variables, met ’n grootte van 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Verseker dat ’n stuk initialization code slegs een keer uitgevoer word. Die grootte daarvan is 12 bytes.
4. **Read-Write Locks:**
- Laat verskeie readers of een writer op ’n slag toe, wat doeltreffende toegang tot shared data moontlik maak.
- **Read Write Lock (Signature: 0x52574c4b):** Het ’n grootte van 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes vir read-write locks, met ’n grootte van 20 bytes.

> [!TIP]
> Die laaste 4 bytes van daardie objects word gebruik om overflows op te spoor.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** word in die konteks van Mach-O-lêers (die formaat vir executables in macOS) gebruik om variables te verklaar wat spesifiek is vir **elke thread** in ’n multi-threaded application. Dit verseker dat elke thread sy eie afsonderlike instance van ’n variable het, wat ’n manier bied om conflicts te vermy en data-integriteit te handhaaf sonder die behoefte aan eksplisiete synchronization mechanisms soos mutexes.

In C en verwante tale kan jy ’n thread-local variable verklaar deur die **`__thread`**-keyword te gebruik. Hier is hoe dit in jou voorbeeld werk:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hierdie snippet definieer `tlv_var` as ’n thread-local variable. Elke thread wat hierdie kode uitvoer, sal sy eie `tlv_var` hê, en veranderinge wat een thread aan `tlv_var` maak, sal nie `tlv_var` in ’n ander thread beïnvloed nie.

In die Mach-O binary word die data wat met thread local variables verband hou, in spesifieke seksies georganiseer:

- **`__DATA.__thread_vars`**: Hierdie seksie bevat die metadata oor die thread-local variables, soos hul tipes en initialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie seksie word gebruik vir thread-local variables wat nie eksplisiet geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir zero-initialized data gereserveer is.

Mach-O verskaf ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local variables te bestuur wanneer ’n thread afsluit. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local data opruim wanneer ’n thread beëindig word.

### Threading Priorities

Om thread priorities te verstaan, moet jy kyk na hoe die operating system besluit watter threads om te laat loop en wanneer. Hierdie besluit word beïnvloed deur die priority level wat aan elke thread toegeken is. In macOS en Unix-like systems word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS) classes.

#### Nice and Renice

1. **Nice:**
- Die `nice`-waarde van ’n process is ’n getal wat sy priority beïnvloed. Elke process het ’n nice-waarde wat van -20 (die hoogste priority) tot 19 (die laagste priority) strek. Die default nice-waarde wanneer ’n process geskep word, is tipies 0.
- ’n Laer nice-waarde (nader aan -20) maak ’n process meer “selfsugtig” en gee dit meer CPU-tyd in vergelyking met ander processes met hoër nice-waardes.
2. **Renice:**
- `renice` is ’n command wat gebruik word om die nice-waarde van ’n reeds-lopende process te verander. Dit kan gebruik word om die priority van processes dinamies aan te pas en hul CPU-tydallokasie te verhoog of te verlaag op grond van nuwe nice-waardes.
- Byvoorbeeld, as ’n process tydelik meer CPU resources benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS) Classes

QoS classes is ’n meer moderne benadering tot die hantering van thread priorities, veral in systems soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS classes laat developers toe om werk in verskillende vlakke te **kategoriseer**, gebaseer op die belangrikheid of dringendheid daarvan. macOS bestuur thread prioritization outomaties op grond van hierdie QoS classes:

1. **User Interactive:**
- Hierdie class is vir take wat tans met die user interaksie het of onmiddellike resultate benodig om ’n goeie user experience te bied. Hierdie take kry die hoogste priority om die interface responsive te hou (bv. animations of event handling).
2. **User Initiated:**
- Take wat deur die user geïnisieer word en waarvan onmiddellike resultate verwag word, soos om ’n document oop te maak of op ’n button te click wat computations vereis. Dit is high-priority take, maar onder user interactive.
3. **Utility:**
- Hierdie take loop lank en wys tipies ’n progress indicator (bv. downloading van files of importing van data). Hulle het ’n laer priority as user-initiated take en hoef nie onmiddellik klaar te maak nie.
4. **Background:**
- Hierdie class is vir take wat in die background loop en nie vir die user sigbaar is nie. Dit kan take soos indexing, syncing of backups insluit. Hulle het die laagste priority en minimale impak op system performance.

Deur QoS classes te gebruik, hoef developers nie die presiese priority numbers te bestuur nie, maar kan hulle eerder op die aard van die taak fokus, waarna die system die CPU resources dienooreenkomstig optimaliseer.

Daarbenewens is daar verskillende **thread scheduling policies** wat gebruik word om ’n stel scheduling parameters te spesifiseer wat die scheduler in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition attacks.

## MacOS Process Abuse

MacOS, soos enige ander operating system, verskaf ’n verskeidenheid metodes en meganismes vir **processes om met mekaar te interaksie, te kommunikeer en data te deel**. Hoewel hierdie tegnieke noodsaaklik is vir doeltreffende system functioning, kan threat actors dit ook abuse om **malicious activities uit te voer**.

### Library Injection

Library Injection is ’n tegniek waarin ’n attacker ’n **process dwing om ’n malicious library te laai**. Nadat dit geïnject is, loop die library binne die context van die target process en gee dit die attacker dieselfde permissions en access as die process.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking behels die **intercepting van function calls** of messages binne sagtewarekode. Deur functions te hook, kan ’n attacker die **gedrag van ’n process wysig**, sensitive data observeer of selfs beheer oor die execution flow verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waardeur afsonderlike processes **data deel en uitruil**. Hoewel IPC fundamenteel is vir baie legitimate applications, kan dit ook misbruik word om process isolation te ondermyn, sensitive information te leak of unauthorized actions uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications wat met spesifieke env variables uitgevoer word, kan kwesbaar wees vir process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die flags `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser attack** uit te voer, wat dit moontlik maak om keystrokes en traffic te steel, cookies te steel, scripts in pages te inject, ensovoorts:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **definieer user interface (UI)-elemente** en hul interaksies binne ’n application. Hulle kan egter **arbitrary commands uitvoer**, en **Gatekeeper keer nie dat ’n reeds-uitgevoerde application weer uitgevoer word** as ’n **NIB file gewysig** is nie. Daarom kan hulle gebruik word om arbitrary programs arbitrary commands te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om sekere java capabilities (soos die **`_JAVA_OPTS`** env variable) te abuse om ’n java application **arbitrary code/commands te laat uitvoer**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om code in .Net applications te inject deur **die .Net debugging functionality te abuse** (dit word nie deur macOS protections soos runtime hardening beskerm nie).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende opsies om ’n Perl script arbitrary code te laat uitvoer in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om ruby env variables te abuse om arbitrary scripts arbitrary code te laat uitvoer:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

As die environment variable **`PYTHONINSPECT`** gestel is, sal die python process in ’n python CLI oorgaan sodra dit klaar is. Dit is ook moontlik om **`PYTHONSTARTUP`** te gebruik om ’n python script aan te dui wat aan die begin van ’n interactive session uitgevoer moet word.\
Let egter daarop dat die **`PYTHONSTARTUP`** script nie uitgevoer sal word wanneer **`PYTHONINSPECT`** die interactive session skep nie.

Ander env variables soos **`PYTHONPATH`** en **`PYTHONHOME`** kan ook nuttig wees om ’n python command arbitrary code te laat uitvoer.

Let daarop dat executables wat met **`pyinstaller`** compiled is, nie hierdie environmental variables sal gebruik nie, selfs al loop hulle met behulp van ’n embedded python.

> [!CAUTION]
> Oor die algemeen kon ek nie ’n manier vind om python arbitrary code te laat uitvoer deur environment variables te abuse nie.\
> Die meeste mense installeer pyhton egter met **Hombrew**, wat pyhton in ’n **writable location** vir die default admin user sal installeer. Jy kan dit hijack met iets soos:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Selfs **root** sal hierdie code uitvoer wanneer python uitgevoer word.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n open source **EndpointSecurity**-gebaseerde application wat process injection detect en blokkeer. Dit is ’n goeie verwysing vir watter signals werklik vanaf ES observeerbaar is, aangesien dit waarsku oor:<sup>[[1]](#references)[[2]](#references)</sup>

- **Injection environment variables** tydens process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** calls — een process wat ’n ander process se task port versoek, wat die prerequisite is om daarin te inject.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron app in debug mode start en enigiemand toelaat om daaraan te attach en code daarin uit te voer.<sup>[[3]](#references)</sup>
- **Symlink/hardlink creation across privilege levels** — die klassieke “plant ’n link as ’n normal user en wys dit na ’n privileged location”-primitive. Let daarop dat **symlinks afgemerk maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die link destination voor creation bloot nie.

### Calls made by other processes

In [**hierdie blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy vind hoe dit moontlik is om die function **`task_name_for_pid`** te gebruik om information te verkry oor ander **processes wat code in ’n process inject**, en om daarna information oor daardie ander process te verkry.<sup>[[4]](#references)</sup>

Let daarop dat jy **dieselfde uid** as die user wat die process uitvoer, of **root**, moet wees om daardie function te call (en dit gee information oor die process terug, nie ’n manier om code te inject nie).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
