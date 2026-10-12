# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes की मूल जानकारी

एक process किसी running executable का instance होता है। हालांकि, processes code नहीं चलाते; यह काम threads करते हैं। इसलिए **processes, running threads के लिए केवल containers होते हैं**, जो memory, descriptors, ports, permissions... उपलब्ध कराते हैं।

परंपरागत रूप से, processes दूसरे processes के भीतर शुरू किए जाते थे (PID 1 को छोड़कर), इसके लिए **`fork`** call किया जाता था, जो current process की बिल्कुल वैसी ही copy बनाता था। फिर **child process** आम तौर पर नया executable load करके चलाने के लिए **`execve`** call करता था। इसके बाद, बिना memory copy किए इस प्रक्रिया को तेज़ बनाने के लिए **`vfork`** पेश किया गया।\
फिर **`posix_spawn`** पेश किया गया, जो एक ही call में **`vfork`** और **`execve`** को जोड़ता है और flags स्वीकार करता है:

- `POSIX_SPAWN_RESETIDS`: effective ids को real ids पर reset करें
- `POSIX_SPAWN_SETPGROUP`: process group affiliation सेट करें
- `POSUX_SPAWN_SETSIGDEF`: signal का default behaviour सेट करें
- `POSIX_SPAWN_SETSIGMASK`: signal mask सेट करें
- `POSIX_SPAWN_SETEXEC`: उसी process में Exec करें (`execve` की तरह, लेकिन अधिक options के साथ)
- `POSIX_SPAWN_START_SUSPENDED`: suspended अवस्था में शुरू करें
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR के बिना शुरू करें
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc के Nano allocator का उपयोग करें
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segments पर `rwx` की अनुमति दें
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: डिफ़ॉल्ट रूप से exec(2) पर सभी file descriptions बंद करें
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide के high bits को randomize करें

इसके अलावा, `posix_spawn` **`posix_spawnattr`** settings स्वीकार करता है, जो spawned process के पहलुओं को नियंत्रित करती हैं, और **`posix_spawn_file_actions`** entries भी स्वीकार करता है, जो file descriptors को संशोधित करती हैं।

जब कोई process समाप्त होता है, तो वह `SIGCHLD` signal के साथ **return code को parent process को भेजता है** (अगर parent समाप्त हो चुका हो, तो नया parent PID 1 होता है)। Parent को `wait4()` या `waitid()` call करके यह value प्राप्त करनी होती है। ऐसा होने तक child zombie state में रहता है। वह अभी भी सूची में दिखाई देता है, लेकिन resources का उपयोग नहीं करता।

### PIDs

PIDs यानी process identifiers, किसी एक process की पहचान करते हैं। XNU में **PIDs** **64bits** के होते हैं, लगातार बढ़ते हैं और **कभी wrap नहीं होते** (abuses से बचने के लिए)।

### Process Groups, Sessions और Coalations

**Processes** को **groups** में रखा जा सकता है, ताकि उन्हें संभालना आसान हो। उदाहरण के लिए, shell script में commands एक ही process group में होते हैं, इसलिए उन्हें `kill` का उपयोग करके एक साथ **signal** करना संभव है।\
Processes को **sessions में group** करना भी संभव है। जब कोई process session शुरू करता है (`setsid(2)`), तो उसके child processes उस session में रखे जाते हैं, जब तक कि वे अपना session शुरू न करें।

Darwin में processes को group करने का एक और तरीका coalition है। किसी coalition में शामिल होने से process को pool resources तक पहुँच मिलती है, वह ledger share कर सकता है या Jetsam का सामना कर सकता है। Coalitions की अलग-अलग roles होती हैं: Leader, XPC service, Extension।

### Credentials और Personae

हर process के पास **credentials** होते हैं, जो system में उसके **privileges की पहचान करते हैं**। हर process का एक primary `uid` और एक primary `gid` होता है (हालांकि वह कई groups का सदस्य हो सकता है)।\
अगर binary में `setuid/setgid` bit हो, तो user और group id बदलना भी संभव है।\
**नए uids/gids सेट** करने के लिए कई functions उपलब्ध हैं।

syscall **`persona`** एक **वैकल्पिक** set of **credentials** उपलब्ध कराता है। किसी persona को अपनाने पर उसके uid, gid और group memberships **एक साथ** लागू हो जाते हैं। [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) में यह struct देखा जा सकता है:

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

1. **POSIX Threads (pthreads):** macOS, POSIX threads (`pthreads`) को सपोर्ट करता है, जो C/C++ के लिए एक standard threading API का हिस्सा हैं। macOS में pthreads का implementation `/usr/lib/system/libsystem_pthread.dylib` में मिलता है, जो सार्वजनिक रूप से उपलब्ध `libpthread` project से आता है। यह library threads बनाने और उन्हें manage करने के लिए ज़रूरी functions देती है।
2. **Threads बनाना:** नए threads बनाने के लिए `pthread_create()` function का इस्तेमाल किया जाता है। अंदरूनी तौर पर, यह function `bsdthread_create()` को call करता है, जो XNU kernel (वह kernel जिस पर macOS आधारित है) का एक lower-level system call है। यह system call `pthread_attr` (attributes) से लिए गए कई flags स्वीकार करता है, जो thread के व्यवहार को निर्दिष्ट करते हैं, जिनमें scheduling policies और stack size शामिल हैं।
   - **Default Stack Size:** नए threads का default stack size 512 KB होता है। यह आम कामों के लिए पर्याप्त है, लेकिन ज़रूरत के अनुसार thread attributes के ज़रिए इसे बढ़ाया या घटाया जा सकता है।
3. **Thread Initialization:** `__pthread_init()` function, thread setup के दौरान अहम भूमिका निभाता है। यह `env[]` argument का इस्तेमाल करके environment variables को parse करता है, जिनमें stack की location और size की जानकारी शामिल हो सकती है।

#### macOS में Thread Termination

1. **Threads से बाहर निकलना:** आम तौर पर `pthread_exit()` call करके threads को terminate किया जाता है। यह function thread को ठीक से बाहर निकलने देता है, ज़रूरी cleanup करता है और thread को किसी भी joiner के पास return value भेजने देता है।
2. **Thread Cleanup:** `pthread_exit()` call करने पर `pthread_terminate()` function invoke होता है, जो thread से जुड़ी सभी structures को हटाता है। यह Mach thread ports (Mach, XNU kernel का communication subsystem है) को deallocate करता है और `bsdthread_terminate` नामक syscall को call करता है, जो thread से जुड़ी kernel-level structures को हटाता है।

#### Synchronization Mechanisms

Shared resources तक पहुंच को manage करने और race conditions से बचने के लिए macOS कई synchronization primitives देता है। Multi-threading environments में data integrity और system stability सुनिश्चित करने के लिए ये अहम हैं:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** Standard mutex, जिसका memory footprint 60 bytes है (mutex के लिए 56 bytes और signature के लिए 4 bytes)।
   - **Fast Mutex (Signature: 0x4d55545A):** Regular mutex जैसा ही, लेकिन तेज़ operations के लिए optimized; इसका आकार भी 60 bytes है।
2. **Condition Variables:**
   - कुछ conditions के पूरा होने का इंतज़ार करने के लिए इस्तेमाल होते हैं। इनका आकार 44 bytes (40 bytes और 4-byte signature) है।
   - **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables के configuration attributes, जिनका आकार 12 bytes है।
3. **Once Variable (Signature: 0x4f4e4345):**
   - यह सुनिश्चित करता है कि initialization code का एक हिस्सा केवल एक बार execute हो। इसका आकार 12 bytes है।
4. **Read-Write Locks:**
   - एक समय में कई readers या एक writer को अनुमति देते हैं, जिससे shared data तक कुशल पहुंच संभव होती है।
   - **Read Write Lock (Signature: 0x52574c4b):** इसका आकार 196 bytes है।
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks के attributes, जिनका आकार 20 bytes है।

> [!TIP]
> इन objects के आखिरी 4 bytes का इस्तेमाल overflows का पता लगाने के लिए किया जाता है।

### Thread Local Variables (TLV)

Mach-O files (macOS में executables का format) के संदर्भ में, **Thread Local Variables (TLV)** का इस्तेमाल ऐसे variables घोषित करने के लिए किया जाता है जो multi-threaded application में **हर thread के लिए अलग** होते हैं। इससे हर thread के पास किसी variable का अपना अलग instance होता है। इस तरह mutexes जैसे explicit synchronization mechanisms की ज़रूरत के बिना conflicts से बचा जा सकता है और data integrity बनाए रखी जा सकती है।

C और संबंधित languages में, **`__thread`** keyword का इस्तेमाल करके thread-local variable घोषित किया जा सकता है। आपके उदाहरण में यह इस तरह काम करता है:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

यह snippet `tlv_var` को thread-local variable के रूप में परिभाषित करता है। इस code को चलाने वाले हर thread का अपना `tlv_var` होगा, और एक thread द्वारा `tlv_var` में किए गए बदलाव दूसरे thread के `tlv_var` को प्रभावित नहीं करेंगे।

Mach-O binary में, thread-local variables से संबंधित data को विशिष्ट sections में व्यवस्थित किया जाता है:

- **`__DATA.__thread_vars`**: इस section में thread-local variables का metadata होता है, जैसे उनके प्रकार और initialization status।
- **`__DATA.__thread_bss`**: इस section का उपयोग उन thread-local variables के लिए किया जाता है जिन्हें स्पष्ट रूप से initialize नहीं किया गया है। यह zero-initialized data के लिए आरक्षित memory का हिस्सा है।

Mach-O में thread के exit होने पर thread-local variables को manage करने के लिए **`tlv_atexit`** नाम का एक विशिष्ट API भी है। यह API आपको **destructors register** करने देती है—ये विशेष functions हैं, जो thread के terminate होने पर thread-local data को साफ़ करते हैं।

### Threading Priorities

Thread priorities को समझने के लिए यह देखना होता है कि operating system यह कैसे तय करता है कि कौन-से threads कब चलेंगे। यह निर्णय हर thread को दिए गए priority level से प्रभावित होता है। macOS और Unix-जैसे systems में, इसे `nice`, `renice` और Quality of Service (QoS) classes जैसी अवधारणाओं के ज़रिए संभाला जाता है।

#### Nice और Renice

1. **Nice:**
   - किसी process का `nice` value एक संख्या है, जो उसकी priority को प्रभावित करती है। हर process का `nice` value -20 (सबसे ज़्यादा priority) से 19 (सबसे कम priority) तक होता है। Process बनते समय उसका default `nice` value आम तौर पर 0 होता है।
   - कम `nice` value (जो -20 के करीब हो) process को दूसरे, ज़्यादा `nice` value वाले processes की तुलना में ज़्यादा CPU time देती है।
2. **Renice:**
   - `renice` एक command है, जिसका उपयोग पहले से चल रहे process का `nice` value बदलने के लिए किया जाता है। नए `nice` values के आधार पर processes को मिलने वाला CPU time बढ़ाने या घटाने के लिए उनकी priority को गतिशील रूप से बदला जा सकता है।
   - उदाहरण के लिए, अगर किसी process को कुछ समय के लिए अधिक CPU resources की ज़रूरत है, तो आप `renice` का उपयोग करके उसका `nice` value कम कर सकते हैं।

#### Quality of Service (QoS) Classes

QoS classes thread priorities को संभालने का अधिक आधुनिक तरीका हैं, खासकर macOS जैसे systems में, जो **Grand Central Dispatch (GCD)** को support करते हैं। QoS classes developers को काम को उसकी अहमियत या तात्कालिकता के आधार पर अलग-अलग levels में **वर्गीकृत** करने देती हैं। macOS इन QoS classes के आधार पर thread prioritization को स्वचालित रूप से manage करता है:

1. **User Interactive:**
   - यह class उन tasks के लिए है जो इस समय user के साथ interact कर रहे हैं या जिन्हें अच्छा user experience देने के लिए तुरंत परिणाम देने होते हैं। Interface को responsive बनाए रखने के लिए इन tasks को सबसे अधिक priority दी जाती है (उदाहरण के लिए, animations या event handling)।
2. **User Initiated:**
   - ये वे tasks हैं जिन्हें user शुरू करता है और जिनसे उसे तुरंत परिणाम की अपेक्षा होती है, जैसे कोई document खोलना या ऐसा button क्लिक करना जिसमें computations की ज़रूरत हो। इनकी priority अधिक होती है, लेकिन User Interactive से कम।
3. **Utility:**
   - ये लंबे समय तक चलने वाले tasks हैं और आम तौर पर progress indicator दिखाते हैं (उदाहरण के लिए, files download करना या data import करना)। इनकी priority user-initiated tasks से कम होती है और इन्हें तुरंत पूरा करने की ज़रूरत नहीं होती।
4. **Background:**
   - यह class उन tasks के लिए है जो background में चलते हैं और user को दिखाई नहीं देते। इनमें indexing, syncing या backups जैसे tasks शामिल हो सकते हैं। इनकी priority सबसे कम होती है और system performance पर इनका असर भी न्यूनतम होता है।

QoS classes का उपयोग करने पर developers को सटीक priority numbers manage करने की ज़रूरत नहीं होती। वे task की प्रकृति पर ध्यान दे सकते हैं और system उसी के अनुसार CPU resources को optimize करता है।

इसके अलावा, अलग-अलग **thread scheduling policies** होती हैं, जिनके ज़रिए scheduling parameters का एक set दिया जाता है, जिन्हें scheduler ध्यान में रखता है। यह `thread_policy_[set/get]` का उपयोग करके किया जा सकता है। यह race condition attacks में उपयोगी हो सकता है।

## macOS Process Abuse

macOS में **processes के बीच interaction, communication और data sharing** के लिए कई mechanisms हैं। हालाँकि ये mechanisms सामान्य system operation के लिए ज़रूरी हैं, attackers इनका दुरुपयोग injection, code execution या data access के लिए कर सकते हैं।

### Library Injection

Library Injection एक ऐसी technique है जिसमें attacker **किसी process को malicious library load करने के लिए मजबूर करता है**। Inject होने के बाद, यह library target process के context में चलती है और attacker को process जैसी ही permissions और access देती है।


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking में software code के भीतर **function calls** या messages को intercept किया जाता है। Functions को hook करके attacker किसी process के **व्यवहार को बदल सकता है**, sensitive data देख सकता है या execution flow पर नियंत्रण हासिल कर सकता है।


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

यह page ARM64 unwind metadata, arm64e PAC constraints और synthetic call chains को कवर करता है।

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) उन अलग-अलग तरीकों को कहते हैं जिनसे अलग-अलग processes **data share और exchange करते हैं**। IPC कई वैध applications के लिए बुनियादी है, लेकिन इसका दुरुपयोग process isolation को निष्प्रभावी करने, sensitive information leak करने या unauthorized actions करने के लिए भी किया जा सकता है।


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

कुछ env variables के साथ चलाए गए Electron applications process injection के प्रति vulnerable हो सकते हैं:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` और `--use-fake-ui-for-media-stream` flags का उपयोग करके **man in the browser attack** करना संभव है। इससे keystrokes, traffic और cookies चुराई जा सकती हैं, pages में scripts inject की जा सकती हैं...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files किसी application के भीतर **user interface (UI) elements और उनके interactions परिभाषित करती हैं**। हालाँकि, वे **arbitrary commands execute** कर सकती हैं और अगर **NIB file को modify किया गया हो**, तो Gatekeeper पहले से execute हो चुके application को दोबारा execute होने से **नहीं रोकता**। इसलिए, इनका उपयोग arbitrary programs से arbitrary commands execute करवाने के लिए किया जा सकता है:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** या **`JDK_JAVA_OPTIONS`** के ज़रिए JVM options inject करके application शुरू होने से पहले Java या native agent load करना संभव है।


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** के ज़रिए `--require` (file) या `--import data:text/javascript,…` (fileless, Node ≥ 20.6) से attacker का JavaScript preload किया जा सकता है; **`NODE_REPL_EXTERNAL_MODULE`** किसी interactive REPL में module load करता है, और **`ELECTRON_RUN_AS_NODE`** Electron binaries पर इन सभी तरीकों को फिर से सक्षम करता है।

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` से पहले **`DOTNET_STARTUP_HOOKS`** के ज़रिए .NET applications में code inject करना संभव है। इसके अलावा, prerequisites मौजूद होने पर .NET debugging functionality का दुरुपयोग भी किया जा सकता है।


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash **`BASH_ENV`** पढ़ता है; interactive POSIX shells **`ENV`** पढ़ते हैं; zsh **`$ZDOTDIR/.zshenv`** पढ़ता है; और fish, **`XDG_CONFIG_HOME`** या **`XDG_DATA_DIRS`** के नीचे मौजूद configuration पढ़ता है। इनमें से हर shell इच्छित command से पहले एक नियंत्रित startup file execute कर सकता है। xtrace enabled होने पर Bash, **`PS4`** में रखे command substitution को भी चलाता है (उदाहरण के लिए, inherited **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** या **`PHP_INI_SCAN_DIR`** के ज़रिए नियंत्रित PHP configuration load की जा सकती है, जिसका **`auto_prepend_file`** target script से पहले execute होता है।

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Standalone Lua interpreter target script को process करने से पहले **`LUA_INIT`** (या उसके version-specific variant) से code या `@file` execute करता है।

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** और **`R_PROFILE`** ऐसे startup profiles पर redirect करते हैं जिनमें R code होता है। इसके बजाय, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** और R library path का उपयोग करके installed package को auto-load किया जा सकता है।

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** उस depot को redirect करता है जिसका `config/startup.jl` अपने आप execute होता है।

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** या **`ERL_ZFLAGS`** payload file की ज़रूरत के बिना Erlang VM में **`-eval`** expression inject कर सकते हैं; Elixir workloads आम तौर पर इसी VM को शुरू करते हैं।

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** और **`OCTAVE_VERSION_INITFILE`** Octave startup scripts को redirect करते हैं।

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` एक cross-platform .NET app है, इसलिए कई environment variables command से पहले code execution संभव बनाते हैं: **`XDG_CONFIG_HOME`** startup पर चलने वाली profile scripts को redirect करता है, **`PSModulePath`** module auto-loading को hijack करता है (planted `.psm1`, import के समय चलता है और built-in cmdlets को shadow कर सकता है), और .NET के **`CORECLR_PROFILER`**/**`COR_PROFILER`** तथा **`DOTNET_STARTUP_HOOKS`** variables `Main` से पहले process में attacker का code load करते हैं।

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script से arbitrary code execute करवाने के अलग-अलग तरीकों के लिए देखें:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary scripts से arbitrary code execute करवाने के लिए Ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) का दुरुपयोग करना भी संभव है:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** और **`BROWSER`** की standard-library chain, warning-filter parsing के दौरान command execute कर सकती है। File-backed विकल्प में `sitecustomize.py` को **`PYTHONPATH`** पर रखा जाता है, ताकि सामान्य `site` initialization target script से पहले उसे import करे। **`PYTHONBREAKPOINT`** code के `breakpoint()` तक पहुँचने पर चुने गए callable/module को चलाता है। केवल interactive mode में काम करने वाले variables, जैसे **`PYTHONSTARTUP`**, का उपयोग सीमित परिस्थितियों में ही किया जा सकता है।

ध्यान दें कि **`pyinstaller`** से compile किए गए executables इन environmental variables का उपयोग नहीं करेंगे, भले ही वे embedded Python के साथ चल रहे हों।

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

सामान्य startup के दौरान **`VIMINIT`** (और उसका `EXINIT` fallback) Ex commands के रूप में execute होते हैं। इसलिए, जब victim नियंत्रित environment के साथ Vim/Neovim खोलता है, तो `:!cmd` / `:call system(...)` से code execution हो सकता है:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

इसके अलावा, Homebrew अक्सर Python को `/opt/homebrew` के नीचे install करता है, जहाँ local `admin` group के members launcher को बदल सकते हैं। यह environment-variable injection के बजाय writable-binary hijack है; इसे exploitable मानने से पहले ownership और ACLs की जाँच करें।


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) एक open-source **EndpointSecurity**-आधारित application है, जो process injection का पता लगाकर उसे block करता है। यह समझने के लिए अच्छा reference है कि Endpoint Security के ज़रिए कौन-से signals देखे जा सकते हैं, क्योंकि यह इन पर alert करता है:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec के समय **Injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` और `ELECTRON_RUN_AS_NODE`।
- **`task_for_pid`** calls — जब एक process दूसरे process का task port माँगता है, जो उसमें inject करने के लिए ज़रूरी है।
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` और `--remote-debugging-port`, जो Electron app को debug mode में शुरू करते हैं और किसी को भी उससे attach होकर उसमें code चलाने देते हैं।<sup>[[3]](#references)</sup>
- **अलग-अलग privilege levels के बीच Symlink/hardlink creation** — इसका पारंपरिक तरीका है “सामान्य user के रूप में link बनाकर उसे किसी privileged location की ओर point करना”। ध्यान दें कि **symlinks पर alert किया जा सकता है, लेकिन उन्हें block नहीं किया जा सकता**: EndpointSecurity, link बनने से पहले उसका destination उपलब्ध नहीं कराता।

### अन्य processes द्वारा की गई calls

[**इस blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) में आप जान सकते हैं कि **`task_name_for_pid`** function का उपयोग करके किसी process में code inject कर रहे दूसरे **processes** की जानकारी और फिर उस दूसरे process के बारे में जानकारी कैसे प्राप्त की जा सकती है।<sup>[[4]](#references)</sup>

ध्यान दें कि इस function को call करने के लिए आपका uid, process चलाने वाले uid के **समान** होना चाहिए या आपको **root** होना चाहिए (यह process की जानकारी देता है, code inject करने का तरीका नहीं)।

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron apps can't store your secrets confidentially क्यों: --inspect विकल्प](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modifications का पता लगाना](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
