# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes की बुनियादी जानकारी

Process किसी चल रहे executable का एक instance होता है, लेकिन processes code नहीं चलाते; यह काम threads करते हैं। इसलिए **processes, चल रहे threads के लिए केवल containers होते हैं** और उन्हें memory, descriptors, ports, permissions... उपलब्ध कराते हैं।

परंपरागत रूप से, processes अन्य processes के भीतर शुरू किए जाते थे (PID 1 को छोड़कर), इसके लिए **`fork`** को call किया जाता था। इससे मौजूदा process की हूबहू copy बनती थी और फिर **child process** आमतौर पर नए executable को load करके चलाने के लिए **`execve`** call करता था। इसके बाद, बिना memory copy किए इस प्रक्रिया को तेज़ करने के लिए **`vfork`** शुरू किया गया।\
फिर, **`vfork`** और **`execve`** को एक call में मिलाने और flags स्वीकार करने के लिए **`posix_spawn`** शुरू किया गया:

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

इसके अलावा, `posix_spawn` **`posix_spawnattr`** settings स्वीकार करता है, जो spawned process के पहलुओं को नियंत्रित करती हैं, और **`posix_spawn_file_actions`** entries स्वीकार करता है, जो file descriptors में बदलाव करती हैं।

जब कोई process समाप्त होता है, तो वह `SIGCHLD` signal के साथ **parent process को return code भेजता है** (अगर parent समाप्त हो गया हो, तो नया parent PID 1 होता है)। Parent को `wait4()` या `waitid()` call करके यह value प्राप्त करनी होती है। ऐसा होने तक child zombie state में रहता है: वह सूची में दिखता है, लेकिन resources का उपभोग नहीं करता।

### PIDs

PIDs, यानी process identifiers, किसी विशिष्ट process की पहचान करते हैं। XNU में **PIDs** **64bits** के होते हैं, लगातार बढ़ते हैं और **कभी wrap नहीं होते** (abuses से बचने के लिए)।

### Process Groups, Sessions और Coalations

**Processes** को **groups** में रखा जा सकता है, ताकि उन्हें संभालना आसान हो। उदाहरण के लिए, shell script में commands एक ही process group में होंगी, इसलिए उन्हें `kill` का उपयोग करके एक साथ **signal किया जा सकता है**।\
Processes को **sessions में group** करना भी संभव है। जब कोई process session शुरू करता है (`setsid(2)`), तो उसके child processes उस session में रखे जाते हैं, जब तक कि वे अपना session शुरू न करें।

Darwin में processes को group करने का एक और तरीका Coalition है। किसी coalition में शामिल होने से process pool resources तक पहुँच सकता है, एक ledger साझा कर सकता है या Jetsam का सामना कर सकता है। Coalations की अलग-अलग भूमिकाएँ होती हैं: Leader, XPC service, Extension।

### Credentials और Personae

हर process के पास **credentials** होते हैं, जो system में उसके **privileges की पहचान करते हैं**। हर process का एक primary `uid` और एक primary `gid` होता है (हालाँकि वह कई groups का सदस्य हो सकता है)।\
अगर binary में `setuid/setgid` bit हो, तो user और group id बदलना भी संभव है।\
**नए uids/gids सेट करने** के लिए कई functions उपलब्ध हैं।

Syscall **`persona`** एक **वैकल्पिक** **credentials** set उपलब्ध कराता है। किसी persona को अपनाने पर उसके uid, gid और group memberships **एक साथ** लागू होते हैं। [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) में यह struct देखा जा सकता है:

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

## थ्रेड्स की मूल जानकारी

1. **POSIX Threads (pthreads):** macOS, POSIX threads (`pthreads`) को सपोर्ट करता है, जो C/C++ के लिए एक मानक threading API का हिस्सा हैं। macOS में pthreads का implementation `/usr/lib/system/libsystem_pthread.dylib` में है, जो सार्वजनिक रूप से उपलब्ध `libpthread` project से आता है। यह library threads बनाने और प्रबंधित करने के लिए आवश्यक functions प्रदान करती है।
2. **Threads बनाना:** नए threads बनाने के लिए `pthread_create()` function का उपयोग किया जाता है। अंदरूनी रूप से, यह function `bsdthread_create()` को कॉल करता है, जो XNU kernel (वह kernel जिस पर macOS आधारित है) के लिए एक निम्न-स्तरीय system call है। यह system call `pthread_attr` (attributes) से प्राप्त विभिन्न flags लेता है, जो scheduling policies और stack size सहित thread के व्यवहार को निर्दिष्ट करते हैं।
   - **डिफ़ॉल्ट Stack Size:** नए threads के लिए डिफ़ॉल्ट stack size 512 KB है, जो सामान्य operations के लिए पर्याप्त है। अधिक या कम जगह की आवश्यकता होने पर इसे thread attributes के ज़रिए बदला जा सकता है।
3. **Thread Initialization:** `__pthread_init()` function, thread setup के दौरान अहम भूमिका निभाता है। यह `env[]` argument का उपयोग करके environment variables को parse करता है, जिनमें stack की location और size की जानकारी शामिल हो सकती है।

#### macOS में Thread Termination

1. **Threads से बाहर निकलना:** आमतौर पर threads को `pthread_exit()` कॉल करके terminate किया जाता है। यह function thread को साफ़ तरीके से बाहर निकलने देता है, ज़रूरी cleanup करता है और thread को join करने वाले किसी भी thread को return value भेजने की सुविधा देता है।
2. **Thread Cleanup:** `pthread_exit()` कॉल करने पर `pthread_terminate()` function invoke होता है, जो thread से जुड़ी सभी structures को हटाता है। यह Mach thread ports को deallocate करता है (Mach, XNU kernel का communication subsystem है) और `bsdthread_terminate` को कॉल करता है—यह एक syscall है, जो thread से जुड़ी kernel-level structures को हटाता है।

#### Synchronization Mechanisms

Shared resources तक पहुँच को प्रबंधित करने और race conditions से बचने के लिए macOS कई synchronization primitives प्रदान करता है। Multi-threading environments में data integrity और system stability बनाए रखने के लिए ये ज़रूरी हैं:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** मानक mutex, जिसका memory footprint 60 bytes है (mutex के लिए 56 bytes और signature के लिए 4 bytes)।
   - **Fast Mutex (Signature: 0x4d55545A):** नियमित mutex के समान, लेकिन तेज़ operations के लिए optimized; इसका आकार भी 60 bytes है।
2. **Condition Variables:**
   - कुछ शर्तों के पूरा होने की प्रतीक्षा के लिए उपयोग किए जाते हैं। इनका आकार 44 bytes है (40 bytes और 4-byte signature)।
   - **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables के configuration attributes, जिनका आकार 12 bytes है।
3. **Once Variable (Signature: 0x4f4e4345):**
   - यह सुनिश्चित करता है कि initialization code का कोई हिस्सा केवल एक बार execute हो। इसका आकार 12 bytes है।
4. **Read-Write Locks:**
   - एक समय में कई readers या एक writer को अनुमति देते हैं, जिससे shared data तक कुशल पहुँच मिलती है।
   - **Read Write Lock (Signature: 0x52574c4b):** इसका आकार 196 bytes है।
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks के attributes, जिनका आकार 20 bytes है।

> [!TIP]
> इन objects के आखिरी 4 bytes का उपयोग overflow का पता लगाने के लिए किया जाता है।

### Thread Local Variables (TLV)

Mach-O files (macOS में executables का format) के संदर्भ में **Thread Local Variables (TLV)** का उपयोग उन variables को declare करने के लिए किया जाता है जो multi-threaded application में **हर thread के लिए अलग** होते हैं। इससे हर thread को किसी variable का अपना अलग instance मिलता है। इस तरह, mutexes जैसे explicit synchronization mechanisms की आवश्यकता के बिना conflicts से बचा जा सकता है और data integrity बनाए रखी जा सकती है।

C और इससे संबंधित भाषाओं में, **`__thread`** keyword का उपयोग करके thread-local variable declare किया जा सकता है। आपके उदाहरण में यह इस तरह काम करता है:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

यह snippet `tlv_var` को thread-local variable के रूप में परिभाषित करता है। इस कोड को चलाने वाले हर thread का अपना `tlv_var` होगा, और एक thread द्वारा `tlv_var` में किए गए बदलाव दूसरे thread के `tlv_var` को प्रभावित नहीं करेंगे।

Mach-O binary में, thread-local variables से संबंधित data को खास sections में व्यवस्थित किया जाता है:

- **`__DATA.__thread_vars`**: इस section में thread-local variables से जुड़ा metadata होता है, जैसे उनके types और initialization status।
- **`__DATA.__thread_bss`**: इस section का उपयोग उन thread-local variables के लिए किया जाता है जिन्हें स्पष्ट रूप से initialize नहीं किया गया है। यह zero-initialized data के लिए अलग रखी गई memory का हिस्सा है।

Mach-O thread के exit होने पर thread-local variables को प्रबंधित करने के लिए **`tlv_atexit`** नाम का एक खास API भी देता है। यह API आपको **destructors register** करने देता है—ये खास functions thread के समाप्त होने पर thread-local data को साफ़ करते हैं।

### Threading प्राथमिकताएँ

Thread priorities को समझने के लिए यह देखना होता है कि operating system कैसे तय करता है कि कौन-से threads चलेंगे और कब। यह निर्णय हर thread को दिए गए priority level से प्रभावित होता है। macOS और Unix-जैसे systems में, इसे `nice`, `renice` और Quality of Service (QoS) classes जैसी अवधारणाओं से नियंत्रित किया जाता है।

#### Nice और Renice

1. **Nice:**
   - किसी process का `nice` value एक संख्या है जो उसकी priority को प्रभावित करती है। हर process का `nice` value -20 (सबसे ऊँची priority) से 19 (सबसे कम priority) तक होता है। Process बनाए जाने पर उसका default `nice` value आम तौर पर 0 होता है।
   - कम `nice` value (जो -20 के करीब हो) process को ज़्यादा "स्वार्थी" बनाता है, जिससे उसे अधिक `nice` value वाले अन्य processes की तुलना में अधिक CPU time मिलता है।
2. **Renice:**
   - `renice` एक command है जिसका उपयोग पहले से चल रहे process का `nice` value बदलने के लिए किया जाता है। नए `nice` values के आधार पर processes को दिए जाने वाले CPU time को बढ़ाने या घटाने के लिए, उनकी priority को गतिशील रूप से समायोजित किया जा सकता है।
   - उदाहरण के लिए, अगर किसी process को कुछ समय के लिए अधिक CPU resources की ज़रूरत हो, तो आप `renice` का उपयोग करके उसका `nice` value कम कर सकते हैं।

#### Quality of Service (QoS) Classes

QoS classes thread priorities को संभालने का एक अधिक आधुनिक तरीका हैं, खासकर macOS जैसे systems में जो **Grand Central Dispatch (GCD)** का समर्थन करते हैं। QoS classes developers को काम को उसके महत्व या तात्कालिकता के आधार पर अलग-अलग levels में **वर्गीकृत** करने देती हैं। macOS इन QoS classes के आधार पर thread prioritization को स्वचालित रूप से प्रबंधित करता है:

1. **User Interactive:**
   - यह class उन tasks के लिए है जो इस समय user के साथ इंटरैक्ट कर रहे हैं या जिन्हें अच्छा user experience देने के लिए तुरंत परिणाम चाहिए। Interface को responsive बनाए रखने के लिए इन tasks को सबसे ऊँची priority दी जाती है (उदाहरण के लिए, animations या event handling)।
2. **User Initiated:**
   - ये वे tasks हैं जिन्हें user शुरू करता है और जिनके परिणाम उसे तुरंत चाहिए, जैसे कोई document खोलना या computations की ज़रूरत वाले button पर click करना। इनकी priority ऊँची होती है, लेकिन User Interactive से कम।
3. **Utility:**
   - ये लंबे समय तक चलने वाले tasks होते हैं और आम तौर पर progress indicator दिखाते हैं (उदाहरण के लिए, files download करना, data import करना)। इनकी priority User Initiated tasks से कम होती है और इन्हें तुरंत पूरा करने की ज़रूरत नहीं होती।
4. **Background:**
   - यह class उन tasks के लिए है जो background में चलते हैं और user को दिखाई नहीं देते। इनमें indexing, syncing या backups जैसे tasks शामिल हो सकते हैं। इनकी priority सबसे कम होती है और system performance पर इनका प्रभाव न्यूनतम होता है।

QoS classes का उपयोग करने पर developers को सटीक priority numbers प्रबंधित करने की ज़रूरत नहीं होती; वे इसके बजाय task की प्रकृति पर ध्यान दे सकते हैं और system उसी के अनुसार CPU resources को optimize करता है।

इसके अलावा, अलग-अलग **thread scheduling policies** होती हैं, जो scheduling parameters का एक set निर्दिष्ट करती हैं जिन्हें scheduler ध्यान में रखता है। यह `thread_policy_[set/get]` का उपयोग करके किया जा सकता है। यह race condition attacks में उपयोगी हो सकता है।

## macOS Process Abuse

macOS में **processes के बीच इंटरैक्शन, communication और data sharing** के लिए कई mechanisms हैं। सामान्य system operation के लिए ये mechanisms आवश्यक हैं, लेकिन attackers injection, code execution या data access के लिए इनका दुरुपयोग कर सकते हैं।

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

Function Hooking में software code के भीतर **function calls** या messages को intercept किया जाता है। Functions को hook करके, attacker किसी process के **व्यवहार को बदल सकता है**, sensitive data देख सकता है या execution flow पर नियंत्रण भी पा सकता है।

{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

इस page में ARM64 unwind metadata, arm64e PAC constraints और synthetic call chains शामिल हैं।

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) उन विभिन्न तरीकों को कहते हैं जिनसे अलग-अलग processes **data साझा और exchange करते हैं**। जहाँ IPC कई वैध applications के लिए बुनियादी है, वहीं इसका दुरुपयोग process isolation को निष्प्रभावी करने, sensitive information को leak करने या अनधिकृत actions करने के लिए भी किया जा सकता है।

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

खास env variables के साथ चलाए गए Electron applications process injection के प्रति vulnerable हो सकते हैं:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` और `--use-fake-ui-for-media-stream` flags का उपयोग करके **man in the browser attack** करना संभव है। इससे keystrokes, traffic और cookies चुराए जा सकते हैं, pages में scripts inject की जा सकती हैं...

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files किसी application के भीतर **user interface (UI) elements और उनके interactions को परिभाषित करती हैं**। हालांकि, ये **arbitrary commands चला सकती हैं**, और अगर कोई **NIB file modify की जाती है**, तो Gatekeeper पहले से चल चुके application को दोबारा चलने से नहीं रोकता। इसलिए इनका उपयोग arbitrary programs से arbitrary commands चलवाने के लिए किया जा सकता है:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** या **`JDK_JAVA_OPTIONS`** के ज़रिए JVM options inject करना और application शुरू होने से पहले Java या native agent load करना संभव है।

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** `--require` (file) या `--import data:text/javascript,…` (fileless, Node ≥ 20.6) के ज़रिए attacker का JavaScript preload करता है; **`NODE_REPL_EXTERNAL_MODULE`** interactive REPL में module load करता है, और **`ELECTRON_RUN_AS_NODE`** Electron binaries पर इन सभी को फिर से सक्षम करता है।

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` से पहले **`DOTNET_STARTUP_HOOKS`** के ज़रिए .NET applications में code inject करना, या prerequisites मौजूद होने पर .NET debugging functionality का दुरुपयोग करना संभव है।

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash **`BASH_ENV`** पढ़ता है; interactive POSIX shells **`ENV`** पढ़ते हैं; zsh **`$ZDOTDIR/.zshenv`** पढ़ता है; और fish **`XDG_CONFIG_HOME`** या **`XDG_DATA_DIRS`** के अंतर्गत configuration पढ़ता है। इनमें से हर एक intended command से पहले नियंत्रित startup file चला सकता है। xtrace सक्षम होने पर Bash **`PS4`** में रखे command substitution को भी चलाता है (उदाहरण के लिए, inherited **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` शुरू करने पर shell standard input से program पढ़ता है। इसलिए, अगर कोई downloader किसी untrusted structured document को पहले parse किए बिना child के stdin में copy करता है, तो पूरा document shell source बन जाता है। एक देखे गए loader ने public iCalendar file को anonymous pipe के ज़रिए, line by line भेजा। Calendar metadata commands के रूप में विफल हुआ, लेकिन zsh तब तक चलता रहा जब तक उसे `DESCRIPTION:` के बाद रखी executable lines नहीं मिलीं। उन lines ने अगला application bundle download करके launch किया। Carrier का expected content type और trusted hosting इसे सुरक्षित नहीं बनाते; खतरनाक सीमा इसकी bytes को interpreter को देना था।<sup>[[5]](#references)</sup>

संबंधित stages [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper और quarantine](../macos-security-protections/macos-gatekeeper.md) और [macOS auto-start locations](../../macos-auto-start-locations.md) में शामिल हैं।

### PHP Injection

**`PHPRC`** या **`PHP_INI_SCAN_DIR`** नियंत्रित PHP configuration load कर सकते हैं, जिसका **`auto_prepend_file`** target script से पहले execute होता है।

[PHP configuration और `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Standalone Lua interpreter target script को process करने से पहले **`LUA_INIT`** (या उसके version-specific variant) से code या `@file` execute करता है।

[Lua `LUA_INIT` startup injection (file और inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** और **`R_PROFILE`** R code वाली startup profiles को redirect करते हैं। **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** और R library path का उपयोग करके installed package को इसके बजाय अपने-आप load किया जा सकता है।

[R startup profiles और package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** उस depot को redirect करता है जिसका `config/startup.jl` अपने-आप execute होता है।

[Julia `JULIA_DEPOT_PATH` और `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** या **`ERL_ZFLAGS`** payload file की आवश्यकता के बिना Erlang VM **`-eval`** expression inject कर सकते हैं; Elixir workloads आम तौर पर उसी VM को शुरू करते हैं।

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** और **`OCTAVE_VERSION_INITFILE`** Octave startup scripts को redirect करते हैं।

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` एक cross-platform .NET app है, इसलिए कई environment variables command से पहले execution की अनुमति देते हैं: **`XDG_CONFIG_HOME`** startup पर चलने वाली profile scripts को redirect करता है, **`PSModulePath`** module auto-loading को hijack करता है (लगाई गई `.psm1` import के समय चलती है और built-in cmdlets की जगह ले सकती है), और .NET के **`CORECLR_PROFILER`**/**`COR_PROFILER`** और **`DOTNET_STARTUP_HOOKS`** variables `Main` से पहले process में attacker code load करते हैं।

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script से arbitrary code execute करवाने के अलग-अलग options यहाँ देखें:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary scripts से arbitrary code execute करवाने के लिए Ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) का दुरुपयोग करना भी संभव है:

[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

**`PYTHONWARNINGS`** और **`BROWSER`** की standard-library chain warning-filter parsing के दौरान command execute कर सकती है। File-backed विकल्प में **`PYTHONPATH`** पर `sitecustomize.py` रखा जाता है, ताकि सामान्य `site` initialization target script से पहले उसे import करे। Code के `breakpoint()` तक पहुँचने पर **`PYTHONBREAKPOINT`** चुने गए callable/module को चलाता है। केवल interactive mode में काम करने वाले variables, जैसे **`PYTHONSTARTUP`**, का उपयोग सीमित परिस्थितियों में किया जा सकता है।

ध्यान दें कि **`pyinstaller`** से compiled executables इन environment variables का उपयोग नहीं करेंगे, भले ही वे embedded Python का उपयोग करके चल रहे हों।

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

सामान्य startup पर **`VIMINIT`** (और उसका fallback `EXINIT`) Ex commands के रूप में execute होते हैं, इसलिए नियंत्रित environment के साथ victim द्वारा Vim/Neovim खोलने पर `:!cmd` / `:call system(...)` code execution दे सकते हैं:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

अलग से, Homebrew आम तौर पर Python को `/opt/homebrew` के नीचे install करता है, जहाँ स्थानीय `admin` group के सदस्य launcher को replace कर सकते हैं। यह environment-variable injection के बजाय writable-binary hijack है; इसे exploitable मानने से पहले ownership और ACLs की जाँच करें।

## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) एक open-source **EndpointSecurity**-आधारित application है जो process injection का पता लगाता है और उसे block करता है। यह Endpoint Security के ज़रिए देखे जा सकने वाले signals का अच्छा संदर्भ है, क्योंकि यह इन पर alert करता है:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec के समय **Injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` और `ELECTRON_RUN_AS_NODE`।
- **`task_for_pid`** calls — एक process द्वारा दूसरे process का task port माँगना, जो उसमें inject करने की पूर्व-आवश्यकता है।
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` और `--remote-debugging-port`; ये Electron app को debug mode में शुरू करते हैं और किसी को भी उससे attach होकर उसमें code चलाने देते हैं।<sup>[[3]](#references)</sup>
- **अलग privilege levels के बीच symlink/hardlink creation** — "सामान्य user के रूप में link बनाकर उसे किसी privileged location की ओर point करना" वाला पारंपरिक तरीका। ध्यान दें कि **symlinks पर alert किया जा सकता है, लेकिन उन्हें block नहीं किया जा सकता**: EndpointSecurity, link बनाए जाने से पहले उसका destination उपलब्ध नहीं कराता।

### दूसरे processes द्वारा की गई calls

[**इस blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) में आप देख सकते हैं कि किसी process में code inject करने वाले अन्य **processes** के बारे में जानकारी पाने, और फिर उस दूसरे process के बारे में जानकारी प्राप्त करने के लिए **`task_name_for_pid`** function का उपयोग कैसे किया जा सकता है।<sup>[[4]](#references)</sup>

ध्यान दें कि उस function को call करने के लिए आपका uid, process चलाने वाले uid के **समान** होना चाहिए या आपको **root** होना चाहिए (और यह process के बारे में जानकारी लौटाता है, code inject करने का तरीका नहीं)।

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — open-source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron apps आपके secrets को गोपनीय रूप से क्यों store नहीं कर सकते: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modifications का पता लगाना](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer का नया version crypto enthusiasts और developers को target करता है](https://securelist.com/macsync-new-version/121383/)
