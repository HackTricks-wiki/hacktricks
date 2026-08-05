# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting oor Prosesse

'n Proses is 'n instansie van 'n uitvoerbare lêer wat loop; prosesse voer egter nie kode uit nie, maar threads. Daarom is **prosesse bloot houers vir threads wat loop**, wat die geheue, descriptors, poorte, toestemmings...

Tradisioneel is prosesse binne ander prosesse begin (behalwe PID 1) deur **`fork`** aan te roep, wat 'n presiese kopie van die huidige proses skep. Die **child process** sou dan gewoonlik **`execve`** aanroep om die nuwe uitvoerbare lêer te laai en dit uit te voer. Daarna is **`vfork`** bekendgestel om hierdie proses vinniger te maak sonder enige geheuek kopiering.\
Daarna is **`posix_spawn`** bekendgestel, wat **`vfork`** en **`execve`** in een oproep kombineer en vlae aanvaar:

- `POSIX_SPAWN_RESETIDS`: Stel effektiewe ids terug na werklike ids
- `POSIX_SPAWN_SETPGROUP`: Stel prosesgroep-affiliasie
- `POSUX_SPAWN_SETSIGDEF`: Stel verstekgedrag vir seine
- `POSIX_SPAWN_SETSIGMASK`: Stel seinmasker
- `POSIX_SPAWN_SETEXEC`: Voer in dieselfde proses uit (soos `execve` met meer opsies)
- `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
- `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano allocator
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` op datasgmente toe
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Maak alle lêerbeskrywings by verstek toe tydens exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer die hoë bisse van die ASLR-skuif

Daarbenewens laat `posix_spawn` toe dat 'n skikking van **`posix_spawnattr`** gespesifiseer word wat sekere aspekte van die spawned process beheer, asook **`posix_spawn_file_actions`** om die toestand van die descriptors te wysig.

Wanneer 'n proses sterf, stuur dit die **return code na die ouerproses** (indien die ouerproses gesterf het, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouerproses moet hierdie waarde met `wait4()` of `waitid()` verkry, en totdat dit gebeur, bly die child process in 'n zombie-toestand waar dit steeds gelys word, maar nie hulpbronne verbruik nie.

### PIDs

PIDs, proses-identifiseerders, identifiseer 'n unieke proses. In XNU is die **PIDs** 64-bis, neem dit monotoon toe en loop dit **nooit om nie** (om misbruik te voorkom).

### Prosesgroepe, Sessies & Coalations

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Opdragte in 'n shell script sal byvoorbeeld in dieselfde prosesgroep wees, sodat dit moontlik is om hulle **saam te sein** deur byvoorbeeld kill te gebruik.\
Dit is ook moontlik om **prosesse in sessies te groepeer**. Wanneer 'n proses 'n sessie begin (`setsid(2)`), word die child processes binne die sessie geplaas, tensy hulle hul eie sessie begin.

Coalition is nog 'n manier om prosesse in Darwin te groepeer. Deur by 'n coalition aan te sluit, kan 'n proses toegang tot pool resources verkry, 'n ledger deel of deur Jetsam geraak word. Coalitions het verskillende rolle: Leader, XPC service, Extension.

### Credentials & Personae

Elke proses **hou credentials** wat **sy privileges** in die stelsel **identifiseer**. Elke proses sal een primêre `uid` en een primêre `gid` hê (hoewel dit aan verskeie groepe kan behoort).\
Dit is ook moontlik om die gebruiker- en groep-ID te verander indien die binary die `setuid/setgid`-bit het.\
Daar is verskeie funksies om **nuwe uids/gids te stel**.

Die syscall **`persona`** verskaf 'n **alternatiewe** stel **credentials**. Deur 'n persona aan te neem, aanvaar dit terselfdertyd sy uid, gid en groeplidmaatskappe. In die [**broncode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) is dit moontlik om die struct te vind:
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

1. **POSIX Threads (pthreads):** macOS ondersteun POSIX Threads (`pthreads`), wat deel is van ’n standaard threading-API vir C/C++. Die implementering van pthreads in macOS word gevind in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die publiek beskikbare `libpthread`-projek. Hierdie library verskaf die nodige funksies om threads te skep en te bestuur.
2. **Creating Threads:** Die `pthread_create()`-funksie word gebruik om nuwe threads te skep. Intern roep hierdie funksie `bsdthread_create()` aan, wat ’n laer-vlak system call is wat spesifiek is aan die XNU-kernel (die kernel waarop macOS gebaseer is). Hierdie system call aanvaar verskeie flags wat van `pthread_attr` (attributes) afgelei word en wat thread-gedrag spesifiseer, insluitend scheduling policies en stack-grootte.
- **Default Stack Size:** Die verstek stack-grootte vir nuwe threads is 512 KB, wat voldoende is vir tipiese bewerkings, maar via thread attributes aangepas kan word indien meer of minder spasie benodig word.
3. **Thread Initialization:** Die `__pthread_init()`-funksie is noodsaaklik tydens thread-opstelling en gebruik die `env[]`-argument om environment variables te ontleed wat besonderhede oor die stack se ligging en grootte kan bevat.

#### Thread Termination in macOS

1. **Exiting Threads:** Threads word gewoonlik beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat ’n thread toe om skoon af te sluit, die nodige cleanup uit te voer en ’n return value aan enige joiners terug te stuur.
2. **Thread Cleanup:** Wanneer `pthread_exit()` aangeroep word, word die `pthread_terminate()`-funksie geïnvokeer. Dit hanteer die verwydering van alle geassosieerde thread structures. Dit deallokeer Mach thread ports (Mach is die communication subsystem in die XNU-kernel) en roep `bsdthread_terminate` aan, ’n syscall wat die kernel-vlak structures wat met die thread geassosieer word, verwyder.

#### Synchronization Mechanisms

Om toegang tot shared resources te bestuur en race conditions te voorkom, verskaf macOS verskeie synchronization primitives. Dit is krities in multi-threading-omgewings om data-integriteit en system stability te verseker:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standard mutex met ’n memory footprint van 60 bytes (56 bytes vir die mutex en 4 bytes vir die signature).
- **Fast Mutex (Signature: 0x4d55545A):** Soortgelyk aan ’n regular mutex, maar geoptimaliseer vir vinniger bewerkings, en ook 60 bytes groot.
2. **Condition Variables:**
- Word gebruik om vir sekere conditions te wag om voor te kom, met ’n grootte van 44 bytes (40 bytes plus ’n 4-byte signature).
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

**Thread Local Variables (TLV)** in die konteks van Mach-O-lêers (die formaat vir executables in macOS) word gebruik om variables te declareer wat spesifiek is vir **elke thread** in ’n multi-threaded application. Dit verseker dat elke thread sy eie aparte instance van ’n variable het, wat ’n manier bied om conflicts te vermy en data-integriteit te handhaaf sonder dat eksplisiete synchronization mechanisms soos mutexes nodig is.

In C en verwante languages kan jy ’n thread-local variable declareer deur die **`__thread`** keyword te gebruik. Hier is hoe dit in jou example werk:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hierdie kodegreep definieer `tlv_var` as ’n thread-local variable. Elke thread wat hierdie kode uitvoer, sal sy eie `tlv_var` hê, en veranderinge wat een thread aan `tlv_var` maak, sal nie `tlv_var` in ’n ander thread beïnvloed nie.

In die Mach-O binary word die data wat met thread-local variables verband hou, in spesifieke seksies georganiseer:

- **`__DATA.__thread_vars`**: Hierdie seksie bevat die metadata oor die thread-local variables, soos hul tipes en initialiseringstatus.
- **`__DATA.__thread_bss`**: Hierdie seksie word gebruik vir thread-local variables wat nie eksplisiet geïnisialiseer is nie. Dit is ’n deel van die geheue wat vir zero-initialized data gereserveer is.

Mach-O verskaf ook ’n spesifieke API genaamd **`tlv_atexit`** om thread-local variables te bestuur wanneer ’n thread afsluit. Hierdie API laat jou toe om **destructors te registreer**—spesiale funksies wat thread-local data opruim wanneer ’n thread beëindig word.

### Threading Priorities

Om thread priorities te verstaan, behels dit om te kyk hoe die operating system besluit watter threads uitgevoer moet word en wanneer. Hierdie besluit word beïnvloed deur die priority level wat aan elke thread toegeken is. In macOS en Unix-like systems word dit hanteer met konsepte soos `nice`, `renice` en Quality of Service (QoS) classes.

#### Nice en Renice

1. **Nice:**
- Die `nice`-waarde van ’n process is ’n nommer wat sy priority beïnvloed. Elke process het ’n nice-waarde wat wissel van -20 (die hoogste priority) tot 19 (die laagste priority). Die default nice-waarde wanneer ’n process geskep word, is gewoonlik 0.
- ’n Laer nice-waarde (nader aan -20) maak ’n process meer "selfish", wat dit meer CPU-tyd gee in vergelyking met ander processes met hoër nice-waardes.
2. **Renice:**
- `renice` is ’n command wat gebruik word om die nice-waarde van ’n process wat reeds loop, te verander. Dit kan gebruik word om die priority van processes dinamies aan te pas, sodat hul CPU-tydtoewysing verhoog of verlaag word op grond van nuwe nice-waardes.
- Byvoorbeeld, as ’n process tydelik meer CPU-resources benodig, kan jy sy nice-waarde met `renice` verlaag.

#### Quality of Service (QoS) Classes

QoS classes is ’n meer moderne benadering tot die hantering van thread priorities, veral in systems soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS classes laat developers toe om werk in verskillende vlakke te **kategoriseer** op grond van die belangrikheid of dringendheid daarvan. macOS bestuur thread prioritization outomaties op grond van hierdie QoS classes:

1. **User Interactive:**
- Hierdie class is vir tasks wat tans met die user interaksie het of onmiddellike resultate benodig om ’n goeie user experience te verskaf. Hierdie tasks kry die hoogste priority om die interface responsief te hou (bv. animations of event handling).
2. **User Initiated:**
- Tasks wat deur die user geïnisieer word en waarvan die user onmiddellike resultate verwag, soos om ’n document oop te maak of ’n button te click wat computations vereis. Dit het ’n hoë priority, maar laer as user interactive.
3. **Utility:**
- Hierdie tasks loop lank en wys gewoonlik ’n progress indicator (bv. die aflaai van files of die importering van data). Hulle het ’n laer priority as user-initiated tasks en hoef nie onmiddellik te voltooi nie.
4. **Background:**
- Hierdie class is vir tasks wat in die background werk en nie vir die user sigbaar is nie. Dit kan tasks soos indexing, syncing of backups insluit. Hulle het die laagste priority en minimale impak op system performance.

Deur QoS classes te gebruik, hoef developers nie die presiese priority-nommers te bestuur nie, maar kan hulle eerder op die aard van die task fokus, waarna die system die CPU-resources dienooreenkomstig optimaliseer.

Daarbenewens is daar verskillende **thread scheduling policies** wat gebruik word om ’n stel scheduling parameters te spesifiseer wat die scheduler in ag sal neem. Dit kan met `thread_policy_[set/get]` gedoen word. Dit kan nuttig wees in race condition attacks.

## MacOS Process Abuse

MacOS, soos enige ander operating system, verskaf ’n verskeidenheid metodes en meganismes vir **processes om met mekaar te interaksie, te kommunikeer en data te deel**. Alhoewel hierdie tegnieke noodsaaklik is vir doeltreffende system functioning, kan threat actors dit ook misbruik om **malicious activities uit te voer**.

### Library Injection

Library Injection is ’n tegniek waarin ’n attacker ’n process **dwing om ’n malicious library te laai**. Sodra dit injected is, loop die library in die context van die target process, wat die attacker dieselfde permissions en access as die process gee.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking behels die **onderskepping van function calls** of messages binne software code. Deur functions te hook, kan ’n attacker die **gedrag van ’n process wysig**, sensitiewe data waarneem of selfs beheer oor die execution flow verkry.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) verwys na verskillende metodes waarvolgens afsonderlike processes **data deel en uitruil**. Alhoewel IPC fundamenteel vir baie legitimate applications is, kan dit ook misbruik word om process isolation te omseil, sensitiewe inligting te leak of unauthorized actions uit te voer.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications wat met spesifieke env variables uitgevoer word, kan kwesbaar wees vir process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Dit is moontlik om die flags `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om ’n **man in the browser attack** uit te voer, wat dit moontlik maak om keystrokes en traffic te steel, cookies te steel, scripts in pages te inject, ens.:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **definieer user interface (UI)-elements** en hul interaksies binne ’n application. Hulle kan egter **arbitrary commands uitvoer**, en **Gatekeeper keer nie dat ’n reeds uitgevoerde application weer uitgevoer word** as ’n **NIB file gewysig word** nie. Daarom kan hulle gebruik word om arbitrary programs arbitrary commands te laat uitvoer:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Dit is moontlik om sekere java capabilities (soos die **`_JAVA_OPTS`** env variable) te misbruik om ’n java application **arbitrary code/commands** te laat uitvoer.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Dit is moontlik om code in .Net applications te inject deur die **.Net debugging functionality te misbruik** (wat nie deur macOS protections soos runtime hardening beskerm word nie).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Kyk na verskillende opsies om ’n Perl script arbitrary code te laat uitvoer in:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Dit is ook moontlik om ruby env variables te misbruik om arbitrary scripts arbitrary code te laat uitvoer:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

As die environment variable **`PYTHONINSPECT`** gestel is, sal die python process in ’n python cli val sodra dit klaar is. Dit is ook moontlik om **`PYTHONSTARTUP`** te gebruik om ’n python script aan te dui wat aan die begin van ’n interactive session uitgevoer moet word.\
Let egter daarop dat die **`PYTHONSTARTUP`** script nie uitgevoer sal word wanneer **`PYTHONINSPECT`** die interactive session skep nie.

Ander env variables soos **`PYTHONPATH`** en **`PYTHONHOME`** kan ook nuttig wees om ’n python command arbitrary code te laat uitvoer.

Let daarop dat executables wat met **`pyinstaller`** compiled is, nie hierdie environmental variables sal gebruik nie, selfs al loop hulle met ’n embedded python.

> [!CAUTION]
> Oor die algemeen kon ek nie ’n manier vind om python arbitrary code te laat uitvoer deur environment variables te misbruik nie.\
> Die meeste mense installeer egter pyhton met **Hombrew**, wat pyhton in ’n **writable location** vir die default admin user installeer. Jy kan dit hijack met iets soos:
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


## Opsporing

### Shield

[**Shield**](https://github.com/theevilbit/Shield) is ’n open source **EndpointSecurity**-gebaseerde application wat process injection opspoor en blokkeer. Dit is ’n goeie verwysing vir watter signals werklik vanaf ES waarneembaar is, aangesien dit waarsku oor:<sup>[[1]](#references)</sup>

- **Injection environment variables** op process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` en `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** calls — een process wat vir ’n ander process se task port vra, wat die prerequisite is om daarin te inject.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` en `--remote-debugging-port`, wat ’n Electron app in debug mode begin en enigiemand toelaat om daaraan te attach en code daarin uit te voer.
- **Symlink/hardlink creation across privilege levels** — die klassieke "plant ’n link as ’n normale user en wys dit na ’n privileged location"-primitive. Let daarop dat **symlinks op gealert kan word, maar nie geblokkeer kan word nie**: EndpointSecurity stel nie die link destination voor creation bloot nie.

### Calls made by other processes

In [**hierdie blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy vind hoe dit moontlik is om die function **`task_name_for_pid`** te gebruik om inligting te kry oor ander **processes wat code in ’n process inject** en dan inligting oor daardie ander process te verkry.<sup>[[4]](#references)</sup>

Let daarop dat jy om daardie function te call, dieselfde uid moet wees as die een waaronder die process loop, of **root** moet wees (en dit gee inligting oor die process terug, nie ’n manier om code te inject nie).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
