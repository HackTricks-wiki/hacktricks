# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes की बुनियादी जानकारी

एक process, चल रहे executable का instance होता है। हालांकि, processes code नहीं चलाते—यह काम threads करते हैं। इसलिए **processes, चल रहे threads के लिए सिर्फ containers होते हैं**, जो memory, descriptors, ports, permissions आदि उपलब्ध कराते हैं।

परंपरागत रूप से, processes दूसरे processes के भीतर शुरू होते थे (PID 1 को छोड़कर), इसके लिए **`fork`** को call किया जाता था। यह मौजूदा process की बिल्कुल सटीक copy बनाता था, जिसके बाद **child process** आम तौर पर नया executable load करके चलाने के लिए **`execve`** को call करता था। फिर, memory copy किए बिना इस प्रक्रिया को तेज़ करने के लिए **`vfork`** पेश किया गया।\
इसके बाद, **`vfork`** और **`execve`** को एक call में मिलाने और flags स्वीकार करने के लिए **`posix_spawn`** पेश किया गया:

- `POSIX_SPAWN_RESETIDS`: effective ids को real ids पर reset करें
- `POSIX_SPAWN_SETPGROUP`: process group affiliation सेट करें
- `POSUX_SPAWN_SETSIGDEF`: signal का default behaviour सेट करें
- `POSIX_SPAWN_SETSIGMASK`: signal mask सेट करें
- `POSIX_SPAWN_SETEXEC`: उसी process में exec करें (`execve` की तरह, लेकिन अधिक options के साथ)
- `POSIX_SPAWN_START_SUSPENDED`: suspended स्थिति में शुरू करें
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR के बिना शुरू करें
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc के Nano allocator का उपयोग करें
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segments पर `rwx` की अनुमति दें
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: डिफ़ॉल्ट रूप से exec(2) पर सभी file descriptions बंद करें
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide के high bits को randomize करें

इसके अलावा, `posix_spawn` **`posix_spawnattr`** settings स्वीकार करता है, जो spawned process के पहलुओं को नियंत्रित करती हैं, और **`posix_spawn_file_actions`** entries भी स्वीकार करता है, जो file descriptors में बदलाव करती हैं।

जब कोई process समाप्त होता है, तो वह **return code को parent process को** भेजता है (अगर parent समाप्त हो गया हो, तो नया parent PID 1 होता है) और `SIGCHLD` signal भी भेजता है। Parent को `wait4()` या `waitid()` call करके यह value प्राप्त करनी होती है। ऐसा होने तक child zombie state में रहता है: वह सूची में दिखता रहता है, लेकिन resources का उपयोग नहीं करता।

### PIDs

PIDs यानी process identifiers, किसी एक process की पहचान करते हैं। XNU में **PIDs**, **64bits** के होते हैं, लगातार बढ़ते हैं और **कभी wrap नहीं होते** (abuses से बचने के लिए)।

### Process Groups, Sessions और Coalations

**Processes** को **groups** में शामिल किया जा सकता है, ताकि उन्हें संभालना आसान हो जाए। उदाहरण के लिए, shell script में commands एक ही process group में होंगी, इसलिए उन्हें एक साथ signal करना संभव है—मसलन, kill का उपयोग करके।\
Processes को **sessions में group** करना भी संभव है। जब कोई process session शुरू करता है (`setsid(2)`), तो उसके child processes उस session में शामिल हो जाते हैं, जब तक कि वे अपना session शुरू न करें।

Darwin में Coalition, processes को group करने का एक और तरीका है। Coalition में शामिल होने से process को pool resources तक पहुंच मिलती है, वह ledger साझा कर सकता है या Jetsam का सामना कर सकता है। Coalitions की अलग-अलग roles होती हैं: Leader, XPC service, Extension।

### Credentials और Personae

हर process के पास **credentials** होते हैं, जो system में उसके **privileges की पहचान करते हैं**। हर process का एक primary `uid` और एक primary `gid` होता है (हालांकि वह कई groups का सदस्य हो सकता है)।\
अगर binary में `setuid/setgid` bit हो, तो user और group id बदलना भी संभव है।\
**नए uids/gids सेट करने** के लिए कई functions उपलब्ध हैं।

Syscall **`persona`** एक **वैकल्पिक** **credentials** set उपलब्ध कराता है। Persona अपनाने पर उसके uid, gid और group memberships **एक साथ** मान्य हो जाते हैं। [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) में यह struct देखा जा सकता है:

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

## Threads की बुनियादी जानकारी

1. **POSIX Threads (pthreads):** macOS, POSIX threads (`pthreads`) को सपोर्ट करता है, जो C/C++ के लिए एक मानक threading API का हिस्सा हैं। macOS में pthreads का implementation `/usr/lib/system/libsystem_pthread.dylib` में मौजूद है, जो सार्वजनिक रूप से उपलब्ध `libpthread` project से आता है। यह library threads बनाने और मैनेज करने के लिए ज़रूरी functions प्रदान करती है।
2. **Threads बनाना:** नए threads बनाने के लिए `pthread_create()` function का उपयोग किया जाता है। आंतरिक रूप से, यह function `bsdthread_create()` को call करता है, जो XNU kernel (वह kernel जिस पर macOS आधारित है) के लिए एक lower-level system call है। यह system call `pthread_attr` (attributes) से लिए गए कई flags स्वीकार करती है, जो scheduling policies और stack size सहित thread के व्यवहार को निर्धारित करते हैं।
   - **Default Stack Size:** नए threads के लिए default stack size 512 KB है। यह सामान्य operations के लिए पर्याप्त है, लेकिन ज़रूरत के अनुसार thread attributes से इसे बढ़ाया या घटाया जा सकता है।
3. **Thread Initialization:** `__pthread_init()` function thread setup के दौरान अहम भूमिका निभाता है। यह `env[]` argument का उपयोग करके environment variables को parse करता है, जिनमें stack की location और size की जानकारी शामिल हो सकती है।

#### macOS में Thread Termination

1. **Threads से बाहर निकलना:** आम तौर पर `pthread_exit()` call करके threads को terminate किया जाता है। यह function thread को साफ़-सुथरे तरीके से बाहर निकलने देता है, ज़रूरी cleanup करता है और thread को किसी भी joiner को return value भेजने देता है।
2. **Thread Cleanup:** `pthread_exit()` call करने पर `pthread_terminate()` function invoke होता है, जो thread से जुड़े सभी structures को हटाता है। यह Mach thread ports को deallocate करता है (Mach, XNU kernel का communication subsystem है) और `bsdthread_terminate` नाम का syscall call करता है, जो thread से जुड़े kernel-level structures को हटाता है।

#### Synchronization Mechanisms

Shared resources तक access मैनेज करने और race conditions से बचने के लिए macOS कई synchronization primitives प्रदान करता है। Multi-threading environments में data integrity और system stability सुनिश्चित करने के लिए ये ज़रूरी हैं:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** मानक mutex, जिसका memory footprint 60 bytes है (mutex के लिए 56 bytes और signature के लिए 4 bytes)।
   - **Fast Mutex (Signature: 0x4d55545A):** Regular mutex जैसा, लेकिन तेज़ operations के लिए optimized; इसका आकार भी 60 bytes है।
2. **Condition Variables:**
   - कुछ conditions के घटित होने की प्रतीक्षा के लिए उपयोग किए जाते हैं। इनका आकार 44 bytes है (40 bytes और 4-byte signature)।
   - **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables के configuration attributes, जिनका आकार 12 bytes है।
3. **Once Variable (Signature: 0x4f4e4345):**
   - यह सुनिश्चित करता है कि initialization code का एक हिस्सा केवल एक बार execute हो। इसका आकार 12 bytes है।
4. **Read-Write Locks:**
   - एक समय में कई readers या एक writer को अनुमति देते हैं, जिससे shared data तक कुशल access मिलता है।
   - **Read Write Lock (Signature: 0x52574c4b):** इसका आकार 196 bytes है।
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks के attributes, जिनका आकार 20 bytes है।

> [!TIP]
> इन objects के आखिरी 4 bytes का उपयोग overflows का पता लगाने के लिए किया जाता है।

### Thread Local Variables (TLV)

Mach-O files (macOS में executables का format) के संदर्भ में **Thread Local Variables (TLV)** का उपयोग ऐसी variables घोषित करने के लिए किया जाता है जो multi-threaded application में **हर thread के लिए अलग-अलग** होती हैं। इससे हर thread को variable का अपना अलग instance मिलता है और mutexes जैसे explicit synchronization mechanisms की ज़रूरत के बिना conflicts से बचने और data integrity बनाए रखने का तरीका मिलता है।

C और संबंधित languages में, आप **`__thread`** keyword का उपयोग करके thread-local variable घोषित कर सकते हैं। आपके उदाहरण में यह इस तरह काम करता है:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

यह snippet `tlv_var` को thread-local variable के रूप में परिभाषित करता है। इस code को चलाने वाले हर thread के पास अपना `tlv_var` होगा, और एक thread द्वारा `tlv_var` में किए गए बदलाव दूसरे thread के `tlv_var` को प्रभावित नहीं करेंगे।

Mach-O binary में, thread-local variables से जुड़ा data विशिष्ट sections में व्यवस्थित होता है:

- **`__DATA.__thread_vars`**: इस section में thread-local variables का metadata होता है, जैसे उनके types और initialization status।
- **`__DATA.__thread_bss`**: इस section का उपयोग उन thread-local variables के लिए होता है जिन्हें स्पष्ट रूप से initialize नहीं किया गया है। यह zero-initialized data के लिए अलग रखी गई memory का हिस्सा है।

Mach-O, thread के बंद होने पर thread-local variables को manage करने के लिए **`tlv_atexit`** नाम का एक विशिष्ट API भी देता है। यह API आपको **destructors register** करने देता है—ये विशेष functions thread के terminate होने पर thread-local data को साफ़ करते हैं।

### Threading Priorities

Thread priorities को समझने के लिए यह देखना होता है कि operating system कैसे तय करता है कि कौन-से threads कब चलेंगे। यह निर्णय हर thread को दिए गए priority level से प्रभावित होता है। macOS और Unix-जैसे systems में, इसे `nice`, `renice` और Quality of Service (QoS) classes जैसी अवधारणाओं के ज़रिए manage किया जाता है।

#### Nice और Renice

1. **Nice:**
   - किसी process की `nice` value एक संख्या होती है, जो उसकी priority को प्रभावित करती है। हर process की nice value -20 (सबसे ऊँची priority) से 19 (सबसे कम priority) तक होती है। Process बनाते समय इसकी default nice value आमतौर पर 0 होती है।
   - कम nice value (जो -20 के करीब हो) process को ज़्यादा "selfish" बनाती है, जिससे उसे अधिक nice value वाले दूसरे processes की तुलना में ज़्यादा CPU time मिलता है।
2. **Renice:**
   - `renice` एक command है, जिसका उपयोग पहले से चल रहे process की nice value बदलने के लिए किया जाता है। इससे नई nice values के आधार पर processes का CPU time allocation बढ़ाकर या घटाकर उनकी priority को गतिशील रूप से बदला जा सकता है।
   - उदाहरण के लिए, अगर किसी process को कुछ समय के लिए ज़्यादा CPU resources की ज़रूरत हो, तो आप `renice` से उसकी nice value कम कर सकते हैं।

#### Quality of Service (QoS) Classes

QoS classes, thread priorities manage करने का एक ज़्यादा आधुनिक तरीका हैं, खासकर macOS जैसे systems में, जो **Grand Central Dispatch (GCD)** को support करते हैं। QoS classes developers को काम को उसकी अहमियत या तात्कालिकता के आधार पर अलग-अलग levels में **वर्गीकृत** करने देती हैं। macOS इन QoS classes के आधार पर thread prioritization को अपने-आप manage करता है:

1. **User Interactive:**
   - यह class उन tasks के लिए है जो इस समय user के साथ interact कर रहे हैं या अच्छा user experience देने के लिए तुरंत परिणाम देने की ज़रूरत है। Interface को responsive बनाए रखने के लिए इन tasks को सबसे ऊँची priority दी जाती है (जैसे animations या event handling)।
2. **User Initiated:**
   - ऐसे tasks जिन्हें user शुरू करता है और जिनसे तुरंत परिणाम की अपेक्षा करता है, जैसे document खोलना या ऐसा button क्लिक करना जिसके लिए computations की ज़रूरत हो। इनकी priority ऊँची होती है, लेकिन User Interactive से कम।
3. **Utility:**
   - ये लंबे समय तक चलने वाले tasks होते हैं और आमतौर पर progress indicator दिखाते हैं (जैसे files download करना, data import करना)। इनकी priority User Initiated tasks से कम होती है और इन्हें तुरंत पूरा करना ज़रूरी नहीं होता।
4. **Background:**
   - यह class background में चलने वाले और user को दिखाई न देने वाले tasks के लिए है। इनमें indexing, syncing या backups जैसे tasks शामिल हो सकते हैं। इनकी priority सबसे कम होती है और system performance पर इनका प्रभाव भी न्यूनतम होता है।

QoS classes का उपयोग करने पर developers को सटीक priority numbers manage करने की ज़रूरत नहीं होती; वे task की प्रकृति पर ध्यान दे सकते हैं और system उसी के अनुसार CPU resources को optimize करता है।

इसके अलावा, **thread scheduling policies** भी होती हैं, जो scheduling parameters का एक set तय करती हैं, जिन पर scheduler विचार करता है। यह `thread_policy_[set/get]` से किया जा सकता है। Race condition attacks में यह उपयोगी हो सकता है।

## macOS Process Abuse

macOS में **processes के बीच interaction, communication और data sharing** के लिए कई mechanisms हैं। हालाँकि ये mechanisms सामान्य system operation के लिए आवश्यक हैं, लेकिन attackers इनका दुरुपयोग injection, code execution या data access के लिए कर सकते हैं।

### Library Injection

Library Injection एक ऐसी technique है जिसमें attacker **किसी process को malicious library load करने के लिए मजबूर करता है**। Inject होने के बाद, library target process के context में चलती है, जिससे attacker को उस process जैसी ही permissions और access मिलते हैं।


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking में software code के भीतर **function calls** या messages को intercept किया जाता है। Functions को hook करके attacker किसी process के **behavior में बदलाव** कर सकता है, sensitive data देख सकता है या execution flow पर नियंत्रण भी पा सकता है।


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

यह page ARM64 unwind metadata, arm64e PAC constraints और synthetic call chains को कवर करता है।

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) उन विभिन्न तरीकों को कहते हैं जिनसे अलग-अलग processes **data share और exchange** करते हैं। हालाँकि IPC कई वैध applications के लिए बुनियादी है, लेकिन इसका दुरुपयोग process isolation को दरकिनार करने, sensitive information leak करने या अनधिकृत actions करने के लिए भी किया जा सकता है।


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

विशिष्ट env variables के साथ चलाए गए Electron applications process injection के लिए vulnerable हो सकते हैं:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

**man in the browser attack** करने के लिए `--load-extension` और `--use-fake-ui-for-media-stream` flags का उपयोग किया जा सकता है। इससे keystrokes, traffic और cookies चुराने, pages में scripts inject करने आदि की अनुमति मिलती है:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files application के भीतर **user interface (UI) elements और उनके interactions को परिभाषित** करती हैं। हालाँकि, वे **मनमाने commands execute कर सकती हैं**, और अगर किसी पहले से execute किए गए application की **NIB file में बदलाव किया जाए**, तो **Gatekeeper उसे दोबारा execute होने से नहीं रोकता**। इसलिए, इनका उपयोग मनमाने programs से मनमाने commands execute कराने के लिए किया जा सकता है:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Application शुरू होने से पहले **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** या **`JDK_JAVA_OPTIONS`** के ज़रिए JVM options inject करके Java या native agent load किया जा सकता है।


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (file) या `--import data:text/javascript,…` (fileless, Node ≥ 20.6) के ज़रिए attacker का JavaScript preload करता है; **`NODE_REPL_EXTERNAL_MODULE`** interactive REPL में module load करता है, और **`ELECTRON_RUN_AS_NODE`** Electron binaries पर इन सभी को फिर से सक्षम करता है।

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` से पहले **`DOTNET_STARTUP_HOOKS`** के ज़रिए .NET applications में code inject किया जा सकता है, या prerequisites मौजूद होने पर .NET debugging functionality का दुरुपयोग किया जा सकता है।


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash **`BASH_ENV`** पढ़ता है; interactive POSIX shells **`ENV`** पढ़ते हैं; zsh **`$ZDOTDIR/.zshenv`** पढ़ता है; और fish, **`XDG_CONFIG_HOME`** या **`XDG_DATA_DIRS`** के नीचे मौजूद configuration पढ़ता है। इनमें से हर एक, इच्छित command से पहले नियंत्रित startup file execute कर सकता है। xtrace सक्षम होने पर (उदाहरण के लिए, inherited **`SHELLOPTS=xtrace`** के साथ) Bash, **`PS4`** में रखे गए command substitution को भी हर बार चलाता है:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` शुरू करने पर shell standard input से program पढ़ता है। इसलिए, अगर कोई downloader किसी untrusted structured document को पहले parse किए बिना child के stdin में copy करता है, तो पूरा document shell source बन जाता है। एक देखे गए loader ने public iCalendar file को anonymous pipe के ज़रिए, line by line भेजा। Calendar metadata commands के रूप में fail हुआ, लेकिन zsh तब तक चलता रहा जब तक उसे `DESCRIPTION:` के बाद रखी गई executable lines नहीं मिलीं। उन lines ने अगला application bundle download करके launch किया। Carrier का अपेक्षित content type और trusted hosting इसे safe नहीं बनाते; असली खतरा उसके bytes को interpreter को सौंपना था।<sup>[[5]](#references)</sup>

इससे जुड़े stages [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) और [macOS auto-start locations](../../macos-auto-start-locations.md) में कवर किए गए हैं।

### PHP Injection

**`PHPRC`** या **`PHP_INI_SCAN_DIR`** से ऐसी नियंत्रित PHP configuration load की जा सकती है जिसका **`auto_prepend_file`** target script से पहले execute होता है।

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Standalone Lua interpreter, target script को process करने से पहले **`LUA_INIT`** (या उसके version-specific variant) से code या `@file` execute करता है।

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** और **`R_PROFILE`** से R code वाली startup profiles का path बदला जा सकता है। इसके बजाय, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** और R library path के ज़रिए installed package को अपने-आप load किया जा सकता है।

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** उस depot का path बदलता है जिसका `config/startup.jl` अपने-आप execute होता है।

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** या **`ERL_ZFLAGS`** से payload file की ज़रूरत के बिना Erlang VM में **`-eval`** expression inject किया जा सकता है; Elixir workloads आमतौर पर इसी VM को शुरू करते हैं।

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** और **`OCTAVE_VERSION_INITFILE`** से Octave startup scripts का path बदला जा सकता है।

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` एक cross-platform .NET app है, इसलिए कई environment variables command से पहले code execution की अनुमति देते हैं: **`XDG_CONFIG_HOME`** startup पर चलने वाली profile scripts का path बदलता है, **`PSModulePath`** module auto-loading को hijack करता है (रखी गई `.psm1` import के समय चलती है और built-in cmdlets की जगह ले सकती है), और .NET के **`CORECLR_PROFILER`**/**`COR_PROFILER`** तथा **`DOTNET_STARTUP_HOOKS`** variables `Main` से पहले process में attacker code load करते हैं।

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script से मनमाना code execute कराने के लिए अलग-अलग options देखें:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

मनमानी scripts से मनमाना code execute कराने के लिए ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) का दुरुपयोग भी किया जा सकता है:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** और **`BROWSER`** की standard-library chain, warning-filter parsing के दौरान command execute कर सकती है। File-backed विकल्प में **`PYTHONPATH`** पर `sitecustomize.py` रखी जाती है, ताकि सामान्य `site` initialization के दौरान target script से पहले उसे import किया जाए। Code के `breakpoint()` तक पहुँचने पर **`PYTHONBREAKPOINT`** चुने हुए callable/module को चलाता है। **`PYTHONSTARTUP`** जैसे केवल interactive mode में लागू होने वाले variables का उपयोग सीमित होता है।

ध्यान दें कि **`pyinstaller`** से compile किए गए executables इन environmental variables का उपयोग नहीं करेंगे, भले ही वे embedded python के ज़रिए चल रहे हों।

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

सामान्य startup के दौरान **`VIMINIT`** (और उसका `EXINIT` fallback) Ex commands के रूप में execute होते हैं। इसलिए, अगर victim नियंत्रित environment के साथ Vim/Neovim खोलता है, तो `:!cmd` / `:call system(...)` से code execution हो सकता है:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

इसके अलावा, Homebrew आमतौर पर Python को `/opt/homebrew` के नीचे install करता है, जहाँ local `admin` group के members launcher को बदल सकते हैं। यह environment-variable injection नहीं, बल्कि writable-binary hijack है; इसे exploitable मानने से पहले ownership और ACLs जाँचें।


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) एक open-source **EndpointSecurity**-based application है, जो process injection का पता लगाता है और उसे block करता है। यह इस बात का अच्छा संदर्भ है कि Endpoint Security के ज़रिए कौन-से signals देखे जा सकते हैं, क्योंकि यह इन पर alert करता है:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec के दौरान **Injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` और `ELECTRON_RUN_AS_NODE`।
- **`task_for_pid`** calls — एक process द्वारा दूसरे process का task port माँगना, जो उसमें injection करने की पूर्वशर्त है।
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` और `--remote-debugging-port`, जो Electron app को debug mode में शुरू करते हैं और किसी को भी उससे attach होकर उसमें code चलाने देते हैं।<sup>[[3]](#references)</sup>
- **Privilege levels के बीच symlink/hardlink बनाना** — "एक सामान्य user के रूप में link बनाकर उसे किसी privileged location पर point करना" वाला पारंपरिक primitive। ध्यान दें कि **symlinks पर alert किया जा सकता है, लेकिन उन्हें block नहीं किया जा सकता**: EndpointSecurity, link बनने से पहले उसका destination उपलब्ध नहीं कराता।

### दूसरे processes द्वारा की गई calls

[**इस blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) में बताया गया है कि **`task_name_for_pid`** function से दूसरे **process में code inject करने वाले processes** के बारे में जानकारी कैसे प्राप्त की जा सकती है, और फिर उस दूसरे process के बारे में जानकारी कैसे हासिल की जा सकती है।<sup>[[4]](#references)</sup>

ध्यान दें कि इस function को call करने के लिए, आपको process चलाने वाले user के **same uid** का होना चाहिए या **root** होना चाहिए (और यह process के बारे में जानकारी देता है, code inject करने का तरीका नहीं)।

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer का नया version crypto enthusiasts और developers को निशाना बनाता है](https://securelist.com/macsync-new-version/121383/)
