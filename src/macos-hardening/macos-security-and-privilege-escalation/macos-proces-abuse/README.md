# macOS-prosesmisbruik

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting oor prosesse

'n Proses is 'n instansie van 'n uitvoerbare lêer wat tans loop; prosesse voer egter nie kode uit nie, maar drade. Daarom is **prosesse bloot houers vir lopende drade** wat die geheue, beskrywers, poorte, toestemmings...

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat 'n presiese kopie van die huidige proses skep, waarna die **kindproses** gewoonlik **`execve`** aanroep om die nuwe uitvoerbare lêer te laai en dit uit te voer. Daarna is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder enige geheuekoppiering.\
Toe is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een oproep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe id's na werklike id's terug
- `POSIX_SPAWN_SETPGROUP`: Stel prosesgroepaffiliasie
- `POSUX_SPAWN_SETSIGDEF`: Stel verstekgedrag vir seine
- `POSIX_SPAWN_SETSIGMASK`: Stel seinmasker
- `POSIX_SPAWN_SETEXEC`: Voer in dieselfde proses uit (soos `execve` met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano-toekenner
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasegmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Sluit alle lêerbeskrywings by exec(2) standaard
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-skuif

Verder laat `posix_spawn` toe dat 'n skikking van **`posix_spawnattr`** gespesifiseer word wat sekere aspekte van die voortgebringde proses beheer, asook **`posix_spawn_file_actions`** om die toestand van die beskrywers te wysig.

Wanneer 'n proses beëindig, stuur dit die **terugkeerkode aan die ouerproses** (indien die ouer beëindig is, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouer moet hierdie waarde verkry deur `wait4()` of `waitid()` aan te roep; totdat dit gebeur, bly die kind in 'n zombietoestand waarin dit steeds gelys word, maar nie hulpbronne gebruik nie.

### PIDs

PIDs, prosesidentifiseerders, identifiseer 'n unieke proses. In XNU is die **PIDs** 64-bis, neem hulle monotoon toe en rol hulle **nooit** om nie (om misbruik te voorkom).

### Prosesgroepe, sessies & koalisies

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in 'n shell-skrip sal byvoorbeeld in dieselfde prosesgroep wees, sodat dit moontlik is om hulle **saam te sein** deur byvoorbeeld kill te gebruik.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer 'n proses 'n sessie begin (`setsid(2)`), word die kinderprosesse binne die sessie geplaas, tensy hulle hul eie sessie begin.

Koalisie is nog 'n manier om prosesse in Darwin te groepeer. Deur by 'n koalisie aan te sluit, kan 'n proses toegang tot hulpbronpoele verkry, 'n grootboek deel of met Jetsam te doen kry. Koalisies het verskillende rolle: Leier, XPC-diens, Uitbreiding.

### Geloofsbriewe & persona's

Elke proses hou **geloofsbriewe** wat sy **voorregte identifiseer** in die stelsel. Elke proses sal een primêre `uid` en een primêre `gid` hê (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander indien die binêre lêer die `setuid/setgid`-bis het.\
Daar is verskeie funksies om **nuwe uid's/gid's te stel**.

Die syscall **`persona`** verskaf 'n **alternatiewe** stel **geloofsbriewe**. Deur 'n persona aan te neem, aanvaar die proses terselfdertyd sy uid, gid en groeplidmaatskappe. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) is dit moontlik om die struktuur te vind:
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
## Basiese Inligting oor Threads

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX threads (`pthreads`), wat deel is van ’n standaard threading API vir C/C++. Die implementering van pthreads in macOS word gevind in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie library verskaf die nodige funksies om threads te skep en te bestuur.
2. **Creating Threads:** Die `pthread_create()`-funksie word gebruik om nuwe threads te skep. Intern roep hierdie funksie `bsdthread_create()` aan, wat ’n laervlak system call is wat spesifiek is tot die XNU-kernel (die kernel waarop macOS gebaseer is). Hierdie system call aanvaar verskeie flags wat van `pthread_attr` (attributes) afgelei word en wat thread-gedrag spesifiseer, insluitend scheduling policies en stack size.
- **Default Stack Size:** Die default stack size vir nuwe threads is 512 KB, wat voldoende is vir tipiese bewerkings, maar via thread attributes aangepas kan word indien meer of minder spasie benodig word.
3. **Thread Initialization:** Die `__pthread_init()`-funksie is noodsaaklik tydens thread-opstelling en gebruik die `env[]`-argument om environment variables te parseer wat besonderhede oor die stack se ligging en grootte kan insluit.

#### Thread Termination in macOS

1. **Exiting Threads:** Threads word tipies beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n thread toe om netjies te exit, die nodige cleanup uit te voer en die thread toe te laat om ’n return value terug te stuur na enige joiners.
2. **Thread Cleanup:** Wanneer `pthread_exit()` aangeroep word, word die funksie `pthread_terminate()` opgeroep. Dit hanteer die verwydering van alle geassosieerde thread structures. Dit deallokeer Mach thread ports (Mach is die communication subsystem in die XNU-kernel) en roep `bsdthread_terminate` aan, ’n syscall wat die kernel-level structures wat met die thread geassosieer word, verwyder.

#### Synchronization Mechanisms

Om toegang tot shared resources te bestuur en race conditions te voorkom, verskaf macOS verskeie synchronization primitives. Dit is krities in multi-threading environments om data-integriteit en system stability te verseker:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standard mutex met ’n memory footprint van 60 bytes (56 bytes vir die mutex en 4 bytes vir die signature).
- **Fast Mutex (Signature: 0x4d55545A):** Soortgelyk aan ’n regular mutex, maar geoptimaliseer vir vinniger operations, en ook 60 bytes groot.
2. **Condition Variables:**
- Word gebruik om te wag vir sekere conditions om voor te kom, met ’n grootte van 44 bytes (40 bytes plus ’n 4-byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes vir condition variables, met ’n grootte van 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Verseker dat ’n stuk initialization code slegs een keer uitgevoer word. Die grootte daarvan is 12 bytes.
4. **Read-Write Locks:**
- Laat multiple readers of een writer op ’n slag toe, wat doeltreffende toegang tot shared data fasiliteer.
- **Read Write Lock (Signature: 0x52574c4b):** Het ’n grootte van 196 bytes.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes vir read-write locks, met ’n grootte van 20 bytes.

> [!TIP]
> Die laaste 4 bytes van daardie objects word gebruik om overflows op te spoor.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** in die konteks van Mach-O-lêers (die formaat vir executables in macOS) word gebruik om variables te verklaar wat spesifiek is vir **elke thread** in ’n multi-threaded application. Dit verseker dat elke thread sy eie aparte instance van ’n variable het, wat ’n manier bied om conflicts te vermy en data-integriteit te handhaaf sonder dat explicit synchronization mechanisms soos mutexes benodig word.

In C en verwante languages kan jy ’n thread-local variable verklaar deur die **`__thread`**-keyword te gebruik. Hier is hoe dit in jou example werk:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hierdie kodegreep definieer `tlv_var` as ’n thread-local variable. Elke thread wat hierdie kode uitvoer, sal sy eie `tlv_var` hê, en veranderinge wat een thread aan `tlv_var` maak, sal nie `tlv_var` in ’n ander thread beïnvloed nie.

In die Mach-O-binary word die data wat met thread-local variables verband hou, in spesifieke seksies georganiseer:

- **`__DATA.__thread_vars`**: Hierdie seksie bevat die metadata oor die thread-local variables, soos hul tipes en initialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie seksie word gebruik vir thread-local variables wat nie eksplisiet geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir nul-geïnisialiseerde data gereserveer is.

Mach-O verskaf ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local variables te bestuur wanneer ’n thread afsluit. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local data opruim wanneer ’n thread beëindig word.

### Threading Priorities

Om thread priorities te verstaan, behels dat daar gekyk word na hoe die bedryfstelsel besluit watter threads om te laat loop en wanneer. Hierdie besluit word beïnvloed deur die priority level wat aan elke thread toegeken is. In macOS en Unix-like systems word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS) classes.

#### Nice and Renice

1. **Nice:**
- Die `nice`-waarde van ’n proses is ’n getal wat sy priority beïnvloed. Elke proses het ’n nice-waarde wat wissel van -20 (die hoogste priority) tot 19 (die laagste priority). Die verstek-nice-waarde wanneer ’n proses geskep word, is gewoonlik 0.
- ’n Laer nice-waarde (nader aan -20) maak ’n proses meer "selfsugtig", wat dit meer CPU-tyd gee in vergelyking met ander prosesse met hoër nice-waardes.
2. **Renice:**
- `renice` is ’n command wat gebruik word om die nice-waarde van ’n proses wat reeds loop, te verander. Dit kan gebruik word om die priority van prosesse dinamies aan te pas en hul CPU-tyd-toewysing te verhoog of te verlaag op grond van nuwe nice-waardes.
- Byvoorbeeld, as ’n proses tydelik meer CPU-resources benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS) Classes

QoS classes is ’n meer moderne benadering tot die hantering van thread priorities, veral in systems soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS classes laat developers toe om werk in verskillende levels te **kategoriseer** op grond van die belangrikheid of dringendheid daarvan. macOS bestuur thread prioritization outomaties op grond van hierdie QoS classes:

1. **User Interactive:**
- Hierdie class is vir take wat tans met die user interaksie het of onmiddellike resultate vereis om ’n goeie user experience te verskaf. Hierdie take kry die hoogste priority om die interface responsief te hou (bv. animations of event handling).
2. **User Initiated:**
- Take wat deur die user geïnisieer word en waarvan onmiddellike resultate verwag word, soos om ’n dokument oop te maak of op ’n button te klik wat computations vereis. Dit het ’n hoë priority, maar is laer as user interactive.
3. **Utility:**
- Hierdie take loop lank en wys gewoonlik ’n progress indicator (bv. die downloading van files of die importing van data). Hulle het ’n laer priority as user-initiated tasks en hoef nie onmiddellik te voltooi nie.
4. **Background:**
- Hierdie class is vir take wat in die background loop en nie vir die user sigbaar is nie. Dit kan take soos indexing, syncing of backups insluit. Hulle het die laagste priority en minimale impak op system performance.

Deur QoS classes te gebruik, hoef developers nie die presiese priority-nommers te bestuur nie, maar kan hulle eerder op die aard van die taak fokus, waarna die system die CPU-resources dienooreenkomstig optimaliseer.

Daarbenewens is daar verskillende **thread scheduling policies** wat ’n stel scheduling parameters spesifiseer wat die scheduler in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition attacks.

## MacOS Process Abuse

MacOS, soos enige ander operating system, verskaf ’n verskeidenheid metodes en meganismes vir **prosesse om met mekaar te interaksie, te kommunikeer en data te deel**. Alhoewel hierdie tegnieke noodsaaklik is vir doeltreffende system functioning, kan threat actors dit ook misbruik om **malicious activities uit te voer**.

### Library Injection

Library Injection is ’n tegniek waarin ’n attacker ’n **proses dwing om ’n malicious library te laai**. Nadat dit geïnject is, loop die library binne die konteks van die target process en gee dit die attacker dieselfde permissions en access as die proses.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking behels die **onderskep van function calls** of messages binne sagtewarekode. Deur functions te hook, kan ’n attacker die **gedrag van ’n proses wysig**, sensitiewe data waarneem of selfs beheer oor die execution flow verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waardeur afsonderlike prosesse **data deel en uitruil**. Alhoewel IPC fundamenteel is vir baie legitimate applications, kan dit ook misbruik word om process isolation te ondermyn, sensitiewe information te leak of unauthorized actions uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications wat met spesifieke env variables uitgevoer word, kan kwesbaar wees vir process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die flags `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser attack** uit te voer, wat dit moontlik maak om keystrokes en traffic te steel, cookies te steel, scripts in pages te injecteer...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **definieer user interface (UI)-elemente** en hul interactions binne ’n application. Hulle kan egter **arbitrary commands uitvoer**, en **Gatekeeper keer nie dat ’n reeds uitgevoerde application weer uitgevoer word** indien ’n **NIB file gewysig** is nie. Daarom kan hulle gebruik word om arbitrary programs arbitrary commands te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om sekere java capabilities (soos die **`_JAVA_OPTS`** env variable) te misbruik om ’n java application **arbitrary code/commands** te laat uitvoer.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om code in .Net applications te injecteer deur **die .Net debugging functionality te misbruik** (wat nie deur macOS protections soos runtime hardening beskerm word nie).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende options om ’n Perl script arbitrary code te laat uitvoer in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om ruby env variables te misbruik om arbitrary scripts arbitrary code te laat uitvoer:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

As die environment variable **`PYTHONINSPECT`** gestel is, sal die python process na ’n python cli oorgaan sodra dit klaar is. Dit is ook moontlik om **`PYTHONSTARTUP`** te gebruik om ’n python script aan te dui wat aan die begin van ’n interactive session uitgevoer moet word.\
Let egter daarop dat die **`PYTHONSTARTUP`** script nie uitgevoer sal word wanneer **`PYTHONINSPECT`** die interactive session skep nie.

Ander env variables soos **`PYTHONPATH`** en **`PYTHONHOME`** kan ook nuttig wees om ’n python command arbitrary code te laat uitvoer.

Let daarop dat executables wat met **`pyinstaller`** saamgestel is, nie hierdie environmental variables sal gebruik nie, selfs al loop hulle met ’n embedded python.

> [!CAUTION]
> Oor die algemeen kon ek nie ’n manier vind om python arbitrary code te laat uitvoer deur environmental variables te misbruik nie.\
> Die meeste mense installeer pyhton egter met **Hombrew**, wat pyhton in ’n **writable location** vir die verstek-admin user sal installeer. Jy kan dit hijack met iets soos:
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

[**Shield**](https://github.com/theevilbit/Shield) is ’n open source **EndpointSecurity**-based application wat process injection opspoor en blokkeer. Dit is ’n goeie verwysing vir watter signals werklik vanuit ES waarneembaar is, aangesien dit waarsku oor:<sup>[1]</sup>

- **Injection environment variables** tydens process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** calls — een proses wat vir ’n ander proses se task port vra, wat die prerequisite is om daarin te injecteer.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron app in debug mode begin en enigiemand toelaat om daaraan te attach en code daarin uit te voer.
- **Symlink/hardlink creation across privilege levels** — die klassieke primitive van "plant ’n link as ’n normal user en laat dit na ’n privileged location wys". Let daarop dat **symlinks op gealert kan word maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die link destination voor creation bloot nie.

### Calls made by other processes

In [**hierdie blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy vind hoe dit moontlik is om die function **`task_name_for_pid`** te gebruik om information te verkry oor ander **prosesse wat code in ’n proses injecteer**, en dan information oor daardie ander proses te verkry.<sup>[4]</sup>

Let daarop dat jy **dieselfde uid** as die een wat die proses uitvoer of **root** moet wees om daardie function te call (en dit gee info oor die proses terug, nie ’n manier om code te injecteer nie).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
