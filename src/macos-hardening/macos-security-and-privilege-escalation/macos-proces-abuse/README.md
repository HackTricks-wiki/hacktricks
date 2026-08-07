# Matumizi Mabaya ya Processes za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi kuhusu Processes

Process ni mfano wa executable inayotekelezwa, hata hivyo processes hazitekelezi code; hizi ni threads. Kwa hiyo, **processes ni containers tu za kuendesha threads** zinazotoa memory, descriptors, ports, permissions...

Kijadi, processes zilianzishwa ndani ya processes nyingine (isipokuwa PID 1) kwa kuita **`fork`**, ambayo ingeunda nakala kamili ya process ya sasa, kisha **child process** kwa kawaida ingeita **`execve`** ili kupakia executable mpya na kuiendesha. Baadaye, **`vfork`** ilianzishwa ili kufanya process hii iwe ya haraka zaidi bila kunakili memory.\
Kisha **`posix_spawn`** ilianzishwa, ikiunganisha **`vfork`** na **`execve`** katika call moja na kukubali flags:

- `POSIX_SPAWN_RESETIDS`: Weka upya effective ids ziwe real ids
- `POSIX_SPAWN_SETPGROUP`: Weka process group affiliation
- `POSUX_SPAWN_SETSIGDEF`: Weka signal default behaviour
- `POSIX_SPAWN_SETSIGMASK`: Weka signal mask
- `POSIX_SPAWN_SETEXEC`: Fanya Exec katika process hiyo hiyo (kama `execve` yenye options zaidi)
- `POSIX_SPAWN_START_SUSPENDED`: Anza ikiwa suspended
- `_POSIX_SPAWN_DISABLE_ASLR`: Anza bila ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Tumia Nano allocator ya libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Ruhusu `rwx` kwenye data segments
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Funga file descriptions zote kwenye exec(2) kwa default
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomize high bits za ASLR slide

Zaidi ya hayo, `posix_spawn` inaruhusu kubainisha array ya **`posix_spawnattr`** inayodhibiti baadhi ya vipengele vya process iliyoanzishwa, pamoja na **`posix_spawn_file_actions`** za kurekebisha hali ya descriptors.

Process inapokufa hutuma **return code kwa parent process** (ikiwa parent alikufa, parent mpya ni PID 1) kwa signal `SIGCHLD`. Parent anahitaji kupata thamani hii kwa kuita `wait4()` au `waitid()`; hadi hilo litokee, child hubaki katika hali ya zombie, ambapo bado imeorodheshwa lakini haitumii resources.

### PIDs

PIDs, yaani process identifiers, hutambulisha process ya kipekee. Katika XNU, **PIDs** zina ukubwa wa **64bits**, huongezeka monotonically na **hazifanyi wrap** (ili kuzuia matumizi mabaya).

### Process Groups, Sessions & Coalations

**Processes** zinaweza kuwekwa katika **groups** ili kurahisisha kuzishughulikia. Kwa mfano, commands katika shell script zitakuwa katika process group moja, hivyo inawezekana **kuzitumia signal kwa pamoja** kwa kutumia kill, kwa mfano.\
Pia inawezekana **kuweka processes katika sessions**. Process inapoanzisha session (`setsid(2)`), child processes huwekwa ndani ya session hiyo, isipokuwa zianzishe session zao wenyewe.

Coalition ni njia nyingine ya kupanga processes katika Darwin. Process inapojiunga na coalition, inaruhusiwa kufikia pool resources, kushiriki ledger au kukabiliwa na Jetsam. Coalations zina roles tofauti: Leader, XPC service, Extension.

### Credentials & Personae

Kila process huwa na **credentials** zinazo **tambua privileges zake** katika mfumo. Kila process itakuwa na `uid` moja ya msingi na `gid` moja ya msingi (ingawa inaweza kuwa katika groups kadhaa).\
Pia inawezekana kubadilisha user na group id ikiwa binary ina bit ya `setuid/setgid`.\
Kuna functions kadhaa za **kuweka uids/gids mpya**.

Syscall **`persona`** hutoa seti **mbadala** ya **credentials**. Kupitisha persona kunachukua uid, gid na group memberships zake **kwa wakati mmoja**. Katika [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) inawezekana kupata struct:
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
## Maelezo ya Msingi kuhusu Threads

1. **POSIX Threads (pthreads):** macOS inasaidia POSIX threads (`pthreads`), ambazo ni sehemu ya standard threading API ya C/C++. Utekelezaji wa pthreads katika macOS unapatikana kwenye `/usr/lib/system/libsystem_pthread.dylib`, ambayo inatokana na project ya `libpthread` inayopatikana hadharani. Library hii hutoa functions zinazohitajika kuunda na kudhibiti threads.
2. **Kuunda Threads:** Function ya `pthread_create()` hutumika kuunda threads mpya. Ndani yake, function hii huita `bsdthread_create()`, ambayo ni system call ya kiwango cha chini iliyo maalum kwa XNU kernel (kernel ambayo macOS inategemea). System call hii hupokea flags mbalimbali zinazotokana na `pthread_attr` (attributes), ambazo hubainisha tabia ya thread, ikiwemo scheduling policies na stack size.
- **Default Stack Size:** Default stack size ya threads mpya ni 512 KB, ambayo inatosha kwa operations za kawaida lakini inaweza kurekebishwa kupitia thread attributes ikiwa nafasi zaidi au kidogo inahitajika.
3. **Thread Initialization:** Function ya `__pthread_init()` ni muhimu wakati wa kusanidi thread, kwa kutumia argument ya `env[]` kuchanganua environment variables ambazo zinaweza kujumuisha maelezo kuhusu location na size ya stack.

#### Thread Termination katika macOS

1. **Kumaliza Threads:** Kwa kawaida threads humalizwa kwa kuita `pthread_exit()`. Function hii huruhusu thread kutoka kwa usafi, ikifanya cleanup inayohitajika na kuruhusu thread kutuma return value kwa joiners wowote.
2. **Thread Cleanup:** Baada ya kuita `pthread_exit()`, function ya `pthread_terminate()` huitwa; function hii hushughulikia kuondoa thread structures zote zinazohusiana. Hu-deallocate Mach thread ports (Mach ni communication subsystem katika XNU kernel) na kuita `bsdthread_terminate`, syscall ambayo huondoa kernel-level structures zinazohusishwa na thread.

#### Synchronization Mechanisms

Ili kudhibiti ufikiaji wa shared resources na kuepuka race conditions, macOS hutoa synchronization primitives kadhaa. Hizi ni muhimu katika multi-threading environments ili kuhakikisha data integrity na system stability:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Mutex ya kawaida yenye memory footprint ya bytes 60 (bytes 56 za mutex na bytes 4 za signature).
- **Fast Mutex (Signature: 0x4d55545A):** Inafanana na regular mutex lakini imeboreshwa kwa operations za haraka zaidi, pia ikiwa na size ya bytes 60.
2. **Condition Variables:**
- Hutumika kusubiri conditions fulani zitokee, ikiwa na size ya bytes 44 (bytes 40 pamoja na signature ya bytes 4).
- **Condition Variable Attributes (Signature: 0x434e4441):** Configuration attributes za condition variables, zenye size ya bytes 12.
3. **Once Variable (Signature: 0x4f4e4345):**
- Huhakikisha kwamba kipande cha initialization code kinatekelezwa mara moja tu. Size yake ni bytes 12.
4. **Read-Write Locks:**
- Huruhusu readers wengi au writer mmoja kwa wakati mmoja, na kuwezesha ufikiaji wenye ufanisi wa shared data.
- **Read Write Lock (Signature: 0x52574c4b):** Ina size ya bytes 196.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Attributes za read-write locks, zenye size ya bytes 20.

> [!TIP]
> Bytes 4 za mwisho za objects hizo hutumika kugundua overflows.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** katika muktadha wa Mach-O files (format ya executables katika macOS) hutumika kutangaza variables ambazo ni maalum kwa **kila thread** katika multi-threaded application. Hii huhakikisha kwamba kila thread ina instance yake tofauti ya variable, na kutoa njia ya kuepuka conflicts na kudumisha data integrity bila kuhitaji synchronization mechanisms za moja kwa moja kama mutexes.

Katika C na languages zinazohusiana, unaweza kutangaza thread-local variable kwa kutumia keyword ya **`__thread`**. Hivi ndivyo inavyofanya kazi katika mfano wako:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Snippet hii inafafanua `tlv_var` kama variable ya thread-local. Kila thread inayotekeleza code hii itakuwa na `tlv_var` yake, na mabadiliko ambayo thread moja hufanya kwenye `tlv_var` hayataathiri `tlv_var` katika thread nyingine.

Katika binary ya Mach-O, data inayohusiana na thread-local variables hupangwa katika sections maalum:

- **`__DATA.__thread_vars`**: Section hii ina metadata kuhusu thread-local variables, kama aina zake na hali ya initialization.
- **`__DATA.__thread_bss`**: Section hii hutumika kwa thread-local variables ambazo hazija-initializewa waziwazi. Ni sehemu ya memory iliyotengwa kwa data iliyo-initializewa kuwa zero.

Mach-O pia hutoa API maalum inayoitwa **`tlv_atexit`** ya kusimamia thread-local variables wakati thread inatoka. API hii huruhusu **kusajili destructors**—functions maalum zinazosafisha thread-local data wakati thread inamalizika.

### Threading Priorities

Kuelewa thread priorities kunahusisha kuangalia jinsi operating system inavyoamua ni threads zipi zitekelezwe na wakati gani. Uamuzi huu huathiriwa na priority level iliyopewa kila thread. Katika macOS na Unix-like systems, hii hushughulikiwa kwa kutumia concepts kama `nice`, `renice`, na Quality of Service (QoS) classes.

#### Nice na Renice

1. **Nice:**
- Thamani ya `nice` ya process ni namba inayoathiri priority yake. Kila process ina nice value kuanzia -20 (priority ya juu zaidi) hadi 19 (priority ya chini zaidi). Nice value ya kawaida process inapoundwa huwa 0.
- Nice value ya chini (iliyo karibu na -20) hufanya process iwe "selfish" zaidi, ikiipa CPU time zaidi ikilinganishwa na processes nyingine zenye nice values za juu.
2. **Renice:**
- `renice` ni command inayotumika kubadilisha nice value ya process ambayo tayari inaendelea. Hii inaweza kutumika kurekebisha priority ya processes kwa dynamically, kwa kuongeza au kupunguza mgao wao wa CPU time kulingana na nice values mpya.
- Kwa mfano, ikiwa process inahitaji CPU resources zaidi kwa muda, unaweza kupunguza nice value yake ukitumia `renice`.

#### Quality of Service (QoS) Classes

QoS classes ni mbinu ya kisasa zaidi ya kushughulikia thread priorities, hasa katika systems kama macOS zinazotumia **Grand Central Dispatch (GCD)**. QoS classes huruhusu developers **kuainisha** kazi katika viwango tofauti kulingana na umuhimu au uharaka wake. macOS husimamia thread prioritization automatically kulingana na QoS classes hizi:

1. **User Interactive:**
- Class hii ni ya tasks zinazoingiliana na user kwa wakati huo au zinazohitaji matokeo ya haraka ili kutoa user experience nzuri. Tasks hizi hupewa priority ya juu zaidi ili interface iendelee kuwa responsive (kwa mfano, animations au event handling).
2. **User Initiated:**
- Tasks zinazoanzishwa na user na ambazo anatarajia zipate matokeo mara moja, kama kufungua document au kubofya button inayohitaji computations. Hizi zina priority ya juu, lakini iko chini ya user interactive.
3. **Utility:**
- Tasks hizi huendelea kwa muda mrefu na kwa kawaida huonyesha progress indicator (kwa mfano, kupakua files au ku-import data). Zina priority ya chini kuliko tasks zilizoanzishwa na user na hazihitaji kumalizika mara moja.
4. **Background:**
- Class hii ni ya tasks zinazoendesha background na hazionekani kwa user. Hizi zinaweza kuwa tasks kama indexing, syncing au backups. Zina priority ya chini zaidi na athari ndogo kwenye system performance.

Kwa kutumia QoS classes, developers hawahitaji kusimamia namba halisi za priority, bali huzingatia aina ya task, na system huboresha matumizi ya CPU resources kulingana na hilo.

Zaidi ya hayo, kuna **thread scheduling policies** tofauti zinazotumiwa kubainisha seti ya scheduling parameters ambazo scheduler itazingatia. Hili linaweza kufanywa kwa kutumia `thread_policy_[set/get]`. Hii inaweza kuwa muhimu katika race condition attacks.

## MacOS Process Abuse

MacOS, kama operating system nyingine yoyote, hutoa mbinu na mechanisms mbalimbali za **processes kuingiliana, kuwasiliana na kushirikiana data**. Ingawa techniques hizi ni muhimu kwa uendeshaji bora wa system, zinaweza pia kutumiwa vibaya na threat actors ili **kufanya shughuli hasidi**.

### Library Injection

Library Injection ni technique ambapo attacker **hulazimisha process kupakia malicious library**. Baada ya ku-injectiwa, library huendesha ndani ya context ya target process, na kumpa attacker permissions na access sawa na za process hiyo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking inahusisha **ku-intercept function calls** au messages ndani ya software code. Kwa ku-hook functions, attacker anaweza **kubadilisha tabia** ya process, kuchunguza sensitive data, au hata kupata control ya execution flow.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) inarejelea mbinu mbalimbali ambazo processes zilizotenganishwa **hutumiana na kushirikiana data**. Ingawa IPC ni msingi wa legitimate applications nyingi, inaweza pia kutumiwa vibaya kuvuruga process isolation, kufanya **leak** ya sensitive information, au kutekeleza actions zisizoidhinishwa.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Electron applications zinazoendeshwa kwa env variables maalum zinaweza kuwa vulnerable kwa process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Inawezekana kutumia flags `--load-extension` na `--use-fake-ui-for-media-stream` kufanya **man in the browser attack**, inayoruhusu kuiba keystrokes, traffic na cookies, na ku-inject scripts kwenye pages...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files **hufafanua user interface (UI) elements** na interactions zake ndani ya application. Hata hivyo, zinaweza **kutekeleza arbitrary commands**, na **Gatekeeper haisimamishi** application ambayo tayari imekwisha-execute kuendelea ku-execute ikiwa **NIB file imebadilishwa**. Kwa hiyo, zinaweza kutumiwa kufanya arbitrary programs zitekeleze arbitrary commands:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Inawezekana kutumia vibaya baadhi ya Java capabilities (kama env variable **`_JAVA_OPTS`**) kufanya Java application itekeleze **arbitrary code/commands**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Inawezekana ku-inject code kwenye .Net applications kwa **kutumia vibaya .Net debugging functionality** (ambayo hailindwi na macOS protections kama runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Angalia options mbalimbali za kufanya Perl script itekeleze arbitrary code katika:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Pia inawezekana kutumia vibaya Ruby env variables kufanya arbitrary scripts zitekeleze arbitrary code:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Ikiwa environment variable **`PYTHONINSPECT`** imewekwa, Python process itaingia kwenye Python CLI mara tu inapomaliza. Pia inawezekana kutumia **`PYTHONSTARTUP`** kubainisha Python script itakayo-execute mwanzoni mwa interactive session.\
Hata hivyo, kumbuka kuwa **`PYTHONSTARTUP`** script haitatekelezwa wakati **`PYTHONINSPECT`** inaunda interactive session.

Env variables nyingine kama **`PYTHONPATH`** na **`PYTHONHOME`** zinaweza pia kuwa useful kufanya Python command itekeleze arbitrary code.

Kumbuka kuwa executables zilizocompilewa kwa **`pyinstaller`** hazitatumia environmental variables hizi hata kama zinaendesha Python iliy embedded.

> [!CAUTION]
> Kwa ujumla, sikuweza kupata njia ya kufanya Python itekeleze arbitrary code kwa kutumia vibaya environment variables.\
> Hata hivyo, watu wengi hu-install Python wakitumia **Hombrew**, ambayo hu-install Python katika **writable location** kwa default admin user. Unaweza kuihijack kwa kitu kama:
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
> Hata **root** ataendesha code hii anapoendesha Python.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) ni open source **EndpointSecurity**-based application inayodetect na ku-block process injection. Ni reference nzuri ya signals ambazo kwa kweli zinaweza kuonekana kutoka ES, kwa kuwa ina-alert kuhusu:<sup>[[1]](#references)[[2]](#references)</sup>

- **Injection environment variables** kwenye process exec: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` na `ELECTRON_RUN_AS_NODE`.
- Calls za **`task_for_pid`** — process moja ikiomba task port ya nyingine, ambayo ni prerequisite ya ku-inject ndani yake.
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` na `--remote-debugging-port`, ambazo huanzisha Electron app katika debug mode na kumruhusu mtu yeyote ku-attach na ku-run code ndani yake.<sup>[[3]](#references)</sup>
- **Symlink/hardlink creation across privilege levels** — primitive ya kawaida ya "kuunda link kama normal user, kisha kui-elekeza kwenye privileged location". Kumbuka kuwa **symlinks zinaweza ku-alertiwa lakini haziwezi ku-blockiwa**: EndpointSecurity haionyeshi link destination kabla ya kuundwa.

### Calls made by other processes

Katika [**blog post hii**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata jinsi inavyowezekana kutumia function **`task_name_for_pid`** kupata information kuhusu **processes zinazo-inject code kwenye process**, na kisha kupata information kuhusu process hiyo nyingine.<sup>[[4]](#references)</sup>

Kumbuka kuwa ili kuita function hiyo unahitaji kuwa na **uid ile ile** na ile inayotumia process, au uwe **root** (na inarudisha information kuhusu process, si njia ya ku-inject code).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
