# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes की मूल जानकारी

एक process चल रहे executable का instance होता है। हालांकि, processes code नहीं चलाते; ये threads होते हैं। इसलिए **processes, threads चलाने के लिए केवल containers होते हैं**, जो memory, descriptors, ports, permissions आदि उपलब्ध कराते हैं।

परंपरागत रूप से, processes दूसरे processes के भीतर शुरू किए जाते थे (PID 1 को छोड़कर)। इसके लिए **`fork`** को call किया जाता था, जो मौजूदा process की हूबहू copy बनाता था। फिर **child process** आम तौर पर नए executable को load करके चलाने के लिए **`execve`** call करता था। इसके बाद, memory copy किए बिना इस process को तेज़ करने के लिए **`vfork`** लाया गया।\
फिर **`posix_spawn`** लाया गया, जो **`vfork`** और **`execve`** को एक call में जोड़ता है और flags स्वीकार करता है:

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

जब कोई process मरता है, तो वह `SIGCHLD` signal के साथ **return code parent process को भेजता है** (अगर parent मर चुका हो, तो नया parent PID 1 होता है)। Parent को `wait4()` या `waitid()` call करके यह value प्राप्त करनी होती है। ऐसा होने तक child zombie state में रहता है। वह सूची में दिखता रहता है, लेकिन resources का उपयोग नहीं करता।

### PIDs

PIDs यानी process identifiers, एक unique process की पहचान करते हैं। XNU में **PIDs** **64bits** के होते हैं, monotonically बढ़ते हैं और **कभी wrap नहीं होते** (abuses को रोकने के लिए)।

### Process Groups, Sessions और Coalitions

**Processes** को **groups** में रखा जा सकता है, ताकि उन्हें संभालना आसान हो। उदाहरण के लिए, shell script में commands एक ही process group में होंगी, इसलिए उन्हें `kill` का उपयोग करके एक साथ **signal करना** संभव है।\
Processes को **sessions में group** करना भी संभव है। जब कोई process session शुरू करता है (`setsid(2)`), तो उसके child processes उस session में रखे जाते हैं, जब तक कि वे अपना अलग session शुरू न करें।

Darwin में processes को group करने का एक और तरीका Coalition है। किसी coalition में शामिल होने से process pool resources तक पहुँच सकता है, ledger साझा कर सकता है या Jetsam का सामना कर सकता है। Coalitions की अलग-अलग roles होती हैं: Leader, XPC service, Extension।

### Credentials और Personae

हर process के पास **credentials** होते हैं, जो system में उसके **privileges की पहचान करते हैं**। हर process का एक primary `uid` और एक primary `gid` होता है (हालांकि वह कई groups का सदस्य हो सकता है)।\
अगर binary में `setuid/setgid` bit हो, तो user और group id बदलना भी संभव है।\
**नए uids/gids सेट करने** के लिए कई functions उपलब्ध हैं।

Syscall **`persona`** credentials का एक **वैकल्पिक** set उपलब्ध कराता है। Persona अपनाने से उसके uid, gid और group memberships **एक साथ** लागू होते हैं। [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) में यह struct देखा जा सकता है:

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

## थ्रेड्स की बुनियादी जानकारी

1. **POSIX Threads (pthreads):** macOS, POSIX threads (`pthreads`) को सपोर्ट करता है, जो C/C++ के लिए एक मानक threading API का हिस्सा हैं। macOS में pthreads का implementation `/usr/lib/system/libsystem_pthread.dylib` में है, जो सार्वजनिक रूप से उपलब्ध `libpthread` project से आता है। यह library थ्रेड बनाने और उन्हें manage करने के लिए आवश्यक functions प्रदान करती है।
2. **थ्रेड बनाना:** नए थ्रेड बनाने के लिए `pthread_create()` function का उपयोग किया जाता है। आंतरिक रूप से, यह function `bsdthread_create()` को call करता है, जो XNU kernel (वह kernel जिस पर macOS आधारित है) के लिए एक lower-level system call है। यह system call `pthread_attr` (attributes) से प्राप्त विभिन्न flags लेता है, जो thread के व्यवहार को निर्दिष्ट करते हैं, जिनमें scheduling policies और stack size शामिल हैं।
   - **डिफ़ॉल्ट Stack Size:** नए थ्रेड्स का डिफ़ॉल्ट stack size 512 KB होता है। यह सामान्य operations के लिए पर्याप्त है, लेकिन ज़रूरत के अनुसार thread attributes के ज़रिए इसे घटाया या बढ़ाया जा सकता है।
3. **थ्रेड Initialization:** थ्रेड सेटअप के दौरान `__pthread_init()` function अहम होता है। यह `env[]` argument का उपयोग करके environment variables को parse करता है, जिनमें stack की location और size की जानकारी शामिल हो सकती है।

#### macOS में थ्रेड Termination

1. **थ्रेड से बाहर निकलना:** आमतौर पर `pthread_exit()` call करके थ्रेड terminate किए जाते हैं। यह function किसी थ्रेड को साफ़-सुथरे ढंग से exit करने, ज़रूरी cleanup करने और join करने वाले किसी भी थ्रेड को return value भेजने की सुविधा देता है।
2. **थ्रेड Cleanup:** `pthread_exit()` call करने पर `pthread_terminate()` function invoke होता है, जो उससे जुड़े सभी thread structures को हटाता है। यह Mach thread ports (Mach, XNU kernel का communication subsystem है) को deallocate करता है और `bsdthread_terminate` को call करता है, जो thread से जुड़े kernel-level structures को हटाने वाला syscall है।

#### Synchronization Mechanisms

Shared resources तक पहुंच manage करने और race conditions से बचने के लिए macOS कई synchronization primitives प्रदान करता है। Data integrity और system stability सुनिश्चित करने के लिए multi-threading environments में ये अहम हैं:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** Standard mutex, जिसका memory footprint 60 bytes है (mutex के लिए 56 bytes और signature के लिए 4 bytes)।
   - **Fast Mutex (Signature: 0x4d55545A):** Regular mutex के समान, लेकिन तेज़ operations के लिए optimized; इसका आकार भी 60 bytes है।
2. **Condition Variables:**
   - कुछ conditions के पूरा होने का इंतज़ार करने के लिए उपयोग किए जाते हैं। इनका आकार 44 bytes (40 bytes और 4-byte signature) होता है।
   - **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables के configuration attributes, जिनका आकार 12 bytes होता है।
3. **Once Variable (Signature: 0x4f4e4345):**
   - यह सुनिश्चित करता है कि initialization code का कोई भाग केवल एक बार execute हो। इसका आकार 12 bytes होता है।
4. **Read-Write Locks:**
   - एक साथ कई readers या एक writer को अनुमति देता है, जिससे shared data तक कुशल पहुंच मिलती है।
   - **Read Write Lock (Signature: 0x52574c4b):** इसका आकार 196 bytes होता है।
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks के attributes, जिनका आकार 20 bytes होता है।

> [!TIP]
> इन objects के आखिरी 4 bytes का उपयोग overflows का पता लगाने के लिए किया जाता है।

### Thread Local Variables (TLV)

Mach-O files (macOS में executables का format) के संदर्भ में **Thread Local Variables (TLV)** का उपयोग ऐसे variables घोषित करने के लिए किया जाता है जो multi-threaded application में **हर थ्रेड के लिए अलग** होते हैं। इससे हर थ्रेड को variable का अपना अलग instance मिलता है। इस तरह, mutexes जैसे explicit synchronization mechanisms की ज़रूरत के बिना conflicts से बचा जा सकता है और data integrity बनी रहती है।

C और संबंधित भाषाओं में, thread-local variable घोषित करने के लिए **`__thread`** keyword का उपयोग किया जा सकता है। आपके उदाहरण में यह इस तरह काम करता है:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

यह snippet `tlv_var` को thread-local variable के रूप में परिभाषित करता है। इस कोड को चलाने वाले हर thread के पास अपना `tlv_var` होगा, और एक thread द्वारा `tlv_var` में किए गए बदलाव दूसरे thread के `tlv_var` को प्रभावित नहीं करेंगे।

Mach-O binary में, thread local variables से संबंधित डेटा को विशिष्ट sections में व्यवस्थित किया जाता है:

- **`__DATA.__thread_vars`**: इस section में thread-local variables के बारे में metadata होता है, जैसे उनके types और initialization status।
- **`__DATA.__thread_bss`**: इस section का उपयोग उन thread-local variables के लिए किया जाता है जिन्हें स्पष्ट रूप से initialize नहीं किया गया है। यह zero-initialized data के लिए निर्धारित memory का हिस्सा है।

Mach-O thread के समाप्त होने पर thread-local variables को manage करने के लिए **`tlv_atexit`** नाम का एक विशिष्ट API भी देता है। यह API आपको **destructors register** करने देता है—ऐसे विशेष functions जो thread समाप्त होने पर thread-local data को साफ़ करते हैं।

### Threading Priorities

Thread priorities को समझने के लिए यह देखना ज़रूरी है कि operating system कैसे तय करता है कि कौन-से threads चलेंगे और कब। यह निर्णय हर thread को दिए गए priority level से प्रभावित होता है। macOS और Unix-जैसे systems में इसे `nice`, `renice`, और Quality of Service (QoS) classes जैसी अवधारणाओं के ज़रिए संभाला जाता है।

#### Nice और Renice

1. **Nice:**
   - किसी process का `nice` value एक संख्या होती है, जो उसकी priority को प्रभावित करती है। हर process का nice value -20 (सबसे ऊँची priority) से 19 (सबसे कम priority) तक होता है। Process बनते समय उसका default nice value आम तौर पर 0 होता है।
   - कम nice value (-20 के करीब) किसी process को अन्य अधिक nice values वाले processes की तुलना में अधिक CPU time देती है।
2. **Renice:**
   - `renice` एक command है, जिसका उपयोग पहले से चल रहे process का nice value बदलने के लिए किया जाता है। नए nice values के आधार पर processes का CPU time allocation बढ़ाने या घटाने के लिए priority को गतिशील रूप से समायोजित किया जा सकता है।
   - उदाहरण के लिए, अगर किसी process को अस्थायी रूप से अधिक CPU resources चाहिए, तो आप `renice` का उपयोग करके उसका nice value घटा सकते हैं।

#### Quality of Service (QoS) Classes

QoS classes thread priorities संभालने का एक अधिक आधुनिक तरीका हैं, खासकर macOS जैसे systems में जो **Grand Central Dispatch (GCD)** को support करते हैं। QoS classes developers को काम को उसकी अहमियत या तात्कालिकता के अनुसार अलग-अलग levels में **वर्गीकृत** करने देती हैं। macOS इन QoS classes के आधार पर thread prioritization को अपने-आप manage करता है:

1. **User Interactive:**
   - यह class उन tasks के लिए है जो अभी user के साथ interact कर रहे हैं या जिन्हें अच्छा user experience देने के लिए तुरंत results चाहिए। Interface को responsive बनाए रखने के लिए इन tasks को सबसे ऊँची priority दी जाती है (जैसे animations या event handling)।
2. **User Initiated:**
   - ये वे tasks हैं जिन्हें user शुरू करता है और जिनसे तुरंत results की अपेक्षा होती है, जैसे कोई document खोलना या computation की ज़रूरत वाला button क्लिक करना। इनकी priority ऊँची होती है, लेकिन User Interactive से कम।
3. **Utility:**
   - ये लंबे समय तक चलने वाले tasks हैं और आम तौर पर progress indicator दिखाते हैं (जैसे files download करना या data import करना)। इनकी priority user-initiated tasks से कम होती है और इन्हें तुरंत पूरा करना ज़रूरी नहीं होता।
4. **Background:**
   - यह class उन tasks के लिए है जो background में चलते हैं और user को दिखाई नहीं देते। इनमें indexing, syncing या backups जैसे tasks शामिल हो सकते हैं। इनकी priority सबसे कम होती है और system performance पर इनका असर न्यूनतम होता है।

QoS classes का उपयोग करके developers को सटीक priority numbers manage करने की ज़रूरत नहीं होती। इसके बजाय वे task के स्वरूप पर ध्यान देते हैं, और system उसी के अनुसार CPU resources को optimize करता है।

इसके अलावा, अलग-अलग **thread scheduling policies** होती हैं जो scheduling parameters का एक set तय करती हैं, जिन पर scheduler विचार करता है। यह `thread_policy_[set/get]` का उपयोग करके किया जा सकता है। यह race condition attacks में उपयोगी हो सकता है।

## macOS Process Abuse

macOS में **processes को interact करने, communicate करने और data share करने** के कई mechanisms हैं। हालाँकि ये mechanisms सामान्य system operation के लिए ज़रूरी हैं, attackers इनका दुरुपयोग injection, code execution या data access के लिए कर सकते हैं।

### Library Injection

Library Injection एक ऐसी technique है जिसमें attacker **किसी process को malicious library load करने के लिए मजबूर करता है**। Inject होने के बाद, library target process के context में चलती है, जिससे attacker को process जैसी ही permissions और access मिलते हैं।


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking में software code के भीतर function calls या messages को **intercept** किया जाता है। Functions को hook करके attacker process के **व्यवहार में बदलाव** कर सकता है, sensitive data देख सकता है, या execution flow पर नियंत्रण भी हासिल कर सकता है।


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

यह page ARM64 unwind metadata, arm64e PAC constraints और synthetic call chains को कवर करता है।

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) उन अलग-अलग तरीकों को कहते हैं जिनसे अलग processes **data share और exchange** करते हैं। IPC कई वैध applications के लिए बुनियादी ज़रूरत है, लेकिन इसका दुरुपयोग process isolation को दरकिनार करने, sensitive जानकारी leak करने या unauthorized actions करने के लिए भी किया जा सकता है।


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

विशिष्ट env variables के साथ चलाए गए Electron applications process injection के प्रति vulnerable हो सकते हैं:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` और `--use-fake-ui-for-media-stream` flags का उपयोग करके **man in the browser attack** करना संभव है। इससे keystrokes, traffic और cookies चुराए जा सकते हैं, pages में scripts inject की जा सकती हैं, आदि:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files application में **user interface (UI) elements और उनके interactions को परिभाषित** करती हैं। हालाँकि, वे **मनमाने commands चला सकती हैं**, और **NIB file में बदलाव होने पर Gatekeeper पहले से चलाए गए application को दोबारा चलने से नहीं रोकता**। इसलिए, इनका उपयोग arbitrary programs से मनमाने commands चलवाने के लिए किया जा सकता है:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`**, या **`JDK_JAVA_OPTIONS`** के ज़रिए JVM options inject करना और application शुरू होने से पहले Java या native agent load करना संभव है।


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (file) या `--import data:text/javascript,…` (fileless, Node ≥ 20.6) के ज़रिए attacker का JavaScript पहले से load करता है; **`NODE_REPL_EXTERNAL_MODULE`** interactive REPL में module load करता है, और **`ELECTRON_RUN_AS_NODE`** Electron binaries पर यह सब फिर से enable करता है।

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

**`DOTNET_STARTUP_HOOKS`** के ज़रिए `Main` से पहले .NET applications में code inject करना, या prerequisites मौजूद होने पर .NET debugging functionality का दुरुपयोग करना संभव है।


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash **`BASH_ENV`** पढ़ता है; interactive POSIX shells **`ENV`** पढ़ते हैं; zsh **`$ZDOTDIR/.zshenv`** पढ़ता है; और fish **`XDG_CONFIG_HOME`** या **`XDG_DATA_DIRS`** के अंतर्गत configuration पढ़ता है। इनमें से हर एक intended command से पहले नियंत्रित startup file चला सकता है। Bash तब भी **`PS4`** में रखे command substitution को चलाता है, जब xtrace enabled हो (उदाहरण के लिए, inherited **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` शुरू करने पर shell standard input से program पढ़ता है। इसलिए, अगर कोई downloader किसी untrusted structured document को पहले parse किए बिना child के stdin में copy करता है, तो पूरा document shell source बन जाता है। एक देखे गए loader ने public iCalendar file को anonymous pipe के ज़रिए line by line भेजा था। Calendar metadata commands के रूप में विफल हुआ, लेकिन zsh तब तक चलता रहा जब तक उसे `DESCRIPTION:` के बाद रखी गई executable lines नहीं मिलीं। उन lines ने अगला application bundle download करके launch किया। Carrier का अपेक्षित content type और trusted hosting इसे सुरक्षित नहीं बनाते; ख़तरनाक सीमा इसकी bytes को interpreter तक पहुँचाना था।<sup>[[5]](#references)</sup>

इससे जुड़े stages [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), और [macOS auto-start locations](../../macos-auto-start-locations.md) में शामिल हैं।

### PHP Injection

**`PHPRC`** या **`PHP_INI_SCAN_DIR`** नियंत्रित PHP configuration load कर सकते हैं, जिसका **`auto_prepend_file`** target script से पहले execute होता है।

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Standalone Lua interpreter target script को process करने से पहले **`LUA_INIT`** (या उसके version-specific variant) से code या `@file` execute करता है।

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** और **`R_PROFILE`**, R code वाली startup profiles पर redirect करते हैं। इसके बजाय, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** और R library path का उपयोग करके installed package को auto-load किया जा सकता है।

[R startup profiles and package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** उस depot पर redirect करता है जिसकी `config/startup.jl` file अपने-आप execute होती है।

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`**, या **`ERL_ZFLAGS`** payload file की ज़रूरत के बिना Erlang VM **`-eval`** expression inject कर सकते हैं; Elixir workloads आम तौर पर उसी VM को शुरू करते हैं।

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** और **`OCTAVE_VERSION_INITFILE`**, Octave startup scripts पर redirect करते हैं।

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` एक cross-platform .NET app है, इसलिए कई environment variables command से पहले execution करा सकते हैं: **`XDG_CONFIG_HOME`** startup पर चलने वाली profile scripts पर redirect करता है, **`PSModulePath`** module auto-loading को hijack करता है (रखी गई `.psm1` file import के समय चलती है और built-in cmdlets की जगह ले सकती है), और .NET के **`CORECLR_PROFILER`**/**`COR_PROFILER`** तथा **`DOTNET_STARTUP_HOOKS`** variables `Main` से पहले process में attacker का code load करते हैं।

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script से arbitrary code execute कराने के लिए अलग-अलग options देखें:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

मनमाने scripts से arbitrary code execute कराने के लिए ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) का दुरुपयोग भी किया जा सकता है:


[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

**`PYTHONWARNINGS`** और **`BROWSER`** की standard-library chain warning-filter parsing के दौरान command execute कर सकती है। File-backed विकल्प के तौर पर, **`PYTHONPATH`** पर `sitecustomize.py` रखी जा सकती है, ताकि सामान्य `site` initialization target script से पहले उसे import करे। Code के `breakpoint()` तक पहुँचने पर **`PYTHONBREAKPOINT`** चुने गए callable/module को चलाता है।

CPython 3.13+ पर **`PYTHONINSPECT`** भी script के बाद **`PYTHONSTARTUP`** file चला सकता है, जब उसका PyREPL terminal पर शुरू होता है।<sup>[[6]](#references)</sup>

ध्यान दें कि **`pyinstaller`** से compile किए गए executables इन environment variables का उपयोग नहीं करेंगे, भले ही वे embedded python का उपयोग करके चल रहे हों।

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (और उसका fallback **`EXINIT`**) सामान्य startup पर Ex commands के रूप में execute होते हैं। इसलिए, जब victim नियंत्रित environment के साथ Vim/Neovim खोलता है, तो `:!cmd` / `:call system(...)` code execution करा सकते हैं:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

अलग से, Homebrew आम तौर पर Python को `/opt/homebrew` के अंतर्गत install करता है, जहाँ स्थानीय `admin` group के सदस्य launcher को बदल पाने में सक्षम हो सकते हैं। यह environment-variable injection नहीं, बल्कि writable-binary hijack है; इसे exploitable मानने से पहले ownership और ACLs जाँचें।


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) एक open-source **EndpointSecurity**-आधारित application है, जो process injection का पता लगाकर उसे block करती है। यह Endpoint Security के ज़रिए देखे जा सकने वाले signals का अच्छा संदर्भ है, क्योंकि यह इन पर alert करती है:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec पर **injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` और `ELECTRON_RUN_AS_NODE`।
- **`task_for_pid`** calls — जब एक process दूसरे के task port के लिए अनुरोध करता है; उसमें inject करने के लिए यह आवश्यक है।
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` और `--remote-debugging-port`, जो Electron app को debug mode में शुरू करते हैं और किसी को भी उससे attach होकर code चलाने देते हैं।<sup>[[3]](#references)</sup>
- **Privilege levels के बीच symlink/hardlink बनाना** — सामान्य user के रूप में link बनाकर उसे privileged location पर point करने का पारंपरिक तरीका। ध्यान दें कि **symlinks पर alert किया जा सकता है, लेकिन उन्हें block नहीं किया जा सकता**: EndpointSecurity link बनने से पहले उसका destination उपलब्ध नहीं कराता।

### Calls made by other processes

[**इस blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) में बताया गया है कि **`task_name_for_pid`** function का उपयोग करके किसी process में code inject कर रहे अन्य **processes** के बारे में जानकारी कैसे प्राप्त की जा सकती है, और फिर उस दूसरे process की जानकारी कैसे ली जा सकती है।<sup>[[4]](#references)</sup>

ध्यान दें कि इस function को call करने के लिए आपका uid उस process को चलाने वाले uid के समान होना चाहिए या आप **root** होने चाहिए (और यह process के बारे में जानकारी देता है, code inject करने का तरीका नहीं)।  



## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer का नया संस्करण crypto enthusiasts और developers को निशाना बनाता है](https://securelist.com/macsync-new-version/121383/)
- [6] [Python command-line and environment — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
