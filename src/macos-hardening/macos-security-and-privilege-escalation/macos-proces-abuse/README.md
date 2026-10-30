# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes की बुनियादी जानकारी

Process, चल रहे executable का एक instance होता है। हालांकि, processes code नहीं चलाते; ये threads होते हैं। इसलिए **processes, threads चलाने के लिए सिर्फ containers होते हैं**, जो memory, descriptors, ports, permissions आदि उपलब्ध कराते हैं।

परंपरागत रूप से, processes दूसरे processes के भीतर शुरू किए जाते थे (PID 1 को छोड़कर), इसके लिए **`fork`** call किया जाता था। इससे मौजूदा process की हूबहू copy बनती थी और फिर **child process** आम तौर पर नया executable load करके चलाने के लिए **`execve`** call करता था। इसके बाद, memory copy किए बिना इस प्रक्रिया को तेज़ करने के लिए **`vfork`** शुरू किया गया।\
फिर, **`posix_spawn`** शुरू किया गया, जो **`vfork`** और **`execve`** को एक call में जोड़ता है और flags स्वीकार करता है:

- `POSIX_SPAWN_RESETIDS`: effective ids को real ids पर रीसेट करें
- `POSIX_SPAWN_SETPGROUP`: process group affiliation सेट करें
- `POSUX_SPAWN_SETSIGDEF`: signal का default behaviour सेट करें
- `POSIX_SPAWN_SETSIGMASK`: signal mask सेट करें
- `POSIX_SPAWN_SETEXEC`: उसी process में Exec करें (`execve` की तरह, लेकिन अधिक options के साथ)
- `POSIX_SPAWN_START_SUSPENDED`: suspended अवस्था में शुरू करें
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR के बिना शुरू करें
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc का Nano allocator इस्तेमाल करें
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segments पर `rwx` की अनुमति दें
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: exec(2) पर सभी file descriptions को डिफ़ॉल्ट रूप से बंद करें
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide के high bits को randomize करें

इसके अलावा, `posix_spawn` **`posix_spawnattr`** settings स्वीकार करता है, जो spawned process के पहलुओं को नियंत्रित करती हैं, और **`posix_spawn_file_actions`** entries स्वीकार करता है, जो file descriptors में बदलाव करती हैं।

जब कोई process मरता है, तो वह `SIGCHLD` signal के साथ **return code parent process को भेजता है** (अगर parent मर गया हो, तो नया parent PID 1 होता है)। Parent को `wait4()` या `waitid()` call करके यह value प्राप्त करनी होती है। ऐसा होने तक child zombie state में रहता है: वह सूची में दिखता है, लेकिन resources का इस्तेमाल नहीं करता।

### PIDs

PIDs यानी process identifiers, किसी एक process की पहचान करते हैं। XNU में **PIDs** **64bits** के होते हैं, लगातार बढ़ते हैं और **कभी wrap नहीं होते** (abuses से बचने के लिए)।

### Process Groups, Sessions और Coalations

**Processes** को **groups** में रखा जा सकता है, ताकि उन्हें संभालना आसान हो। उदाहरण के लिए, shell script में commands एक ही process group में होते हैं, इसलिए उन्हें kill का इस्तेमाल करके एक साथ **signal किया जा सकता है**।\
Processes को **sessions में group** करना भी संभव है। जब कोई process session शुरू करता है (`setsid(2)`), तो उसके child processes उस session में रखे जाते हैं, जब तक कि वे अपना session शुरू न करें।

Darwin में processes को group करने का एक और तरीका Coalition है। Coalition में शामिल होने से process को pool resources तक पहुंच मिलती है, वह ledger साझा कर सकता है या Jetsam का सामना कर सकता है। Coalations की अलग-अलग भूमिकाएं होती हैं: Leader, XPC service, Extension।

### Credentials और Personae

हर process के पास **credentials** होते हैं, जो सिस्टम में उसके **privileges की पहचान करते हैं**। हर process का एक primary `uid` और एक primary `gid` होता है (हालांकि वह कई groups का सदस्य हो सकता है)।\
अगर binary पर `setuid/setgid` bit सेट हो, तो user और group id बदलना भी संभव है।\
**नए uids/gids सेट करने** के लिए कई functions हैं।

**`persona`** syscall, **credentials** का एक **वैकल्पिक** set उपलब्ध कराता है। Persona अपनाने पर उसके uid, gid और group memberships **एक साथ** लागू होते हैं। [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) में यह struct देखा जा सकता है:

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

1. **POSIX Threads (pthreads):** macOS POSIX threads (`pthreads`) को सपोर्ट करता है, जो C/C++ के लिए एक मानक threading API का हिस्सा हैं। macOS में pthreads का implementation `/usr/lib/system/libsystem_pthread.dylib` में मिलता है, जो सार्वजनिक रूप से उपलब्ध `libpthread` project से आता है। यह library threads बनाने और प्रबंधित करने के लिए आवश्यक functions उपलब्ध कराती है।
2. **Threads बनाना:** नए threads बनाने के लिए `pthread_create()` function का उपयोग किया जाता है। अंदरूनी तौर पर, यह function `bsdthread_create()` को call करता है, जो XNU kernel (जिस पर macOS आधारित है) के लिए एक निम्न-स्तरीय system call है। यह system call `pthread_attr` (attributes) से लिए गए विभिन्न flags स्वीकार करता है, जो thread के व्यवहार को निर्दिष्ट करते हैं—इनमें scheduling policies और stack size शामिल हैं।
   - **डिफ़ॉल्ट Stack Size:** नए threads का डिफ़ॉल्ट stack size 512 KB होता है। यह सामान्य operations के लिए पर्याप्त है, लेकिन ज़रूरत पड़ने पर thread attributes के ज़रिए इसे बढ़ाया या घटाया जा सकता है।
3. **Thread Initialization:** `__pthread_init()` function thread setup के दौरान महत्वपूर्ण होता है। यह `env[]` argument का उपयोग करके environment variables को parse करता है, जिनमें stack की जगह और size से जुड़ी जानकारी हो सकती है।

#### macOS में Thread Termination

1. **Threads से बाहर निकलना:** आम तौर पर `pthread_exit()` call करके threads को terminate किया जाता है। यह function thread को साफ़-सुथरे ढंग से बाहर निकलने देता है, आवश्यक cleanup करता है और thread को किसी भी joiner को return value भेजने देता है।
2. **Thread Cleanup:** `pthread_exit()` call करने पर `pthread_terminate()` function invoke होता है, जो thread से जुड़े सभी structures को हटाता है। यह Mach thread ports (Mach, XNU kernel का communication subsystem है) को deallocate करता है और `bsdthread_terminate` call करता है—यह एक syscall है, जो thread से जुड़े kernel-level structures को हटाता है।

#### Synchronization Mechanisms

Shared resources तक पहुँच को प्रबंधित करने और race conditions से बचने के लिए macOS कई synchronization primitives उपलब्ध कराता है। Multi-threading environments में data integrity और system stability सुनिश्चित करने के लिए ये महत्वपूर्ण हैं:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** मानक mutex, जिसका memory footprint 60 bytes है (mutex के लिए 56 bytes और signature के लिए 4 bytes)।
   - **Fast Mutex (Signature: 0x4d55545A):** Regular mutex जैसा ही, लेकिन तेज़ operations के लिए optimized; इसका size भी 60 bytes है।
2. **Condition Variables:**
   - कुछ conditions होने तक प्रतीक्षा करने के लिए उपयोग किए जाते हैं। इनका size 44 bytes है (40 bytes और 4-byte signature)।
   - **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables के configuration attributes, जिनका size 12 bytes है।
3. **Once Variable (Signature: 0x4f4e4345):**
   - यह सुनिश्चित करता है कि initialization code का कोई हिस्सा केवल एक बार execute हो। इसका size 12 bytes है।
4. **Read-Write Locks:**
   - एक समय में कई readers या एक writer को अनुमति देते हैं, जिससे shared data तक कुशल पहुँच मिलती है।
   - **Read Write Lock (Signature: 0x52574c4b):** इसका size 196 bytes है।
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks के attributes, जिनका size 20 bytes है।

> [!TIP]
> इन objects के आखिरी 4 bytes का उपयोग overflow का पता लगाने के लिए किया जाता है।

### Thread Local Variables (TLV)

Mach-O files (macOS में executables का format) के संदर्भ में **Thread Local Variables (TLV)** का उपयोग उन variables को घोषित करने के लिए किया जाता है जो multi-threaded application में **हर thread** के लिए अलग होते हैं। इससे हर thread के पास variable का अपना अलग instance होता है। इस तरह, mutexes जैसे explicit synchronization mechanisms की ज़रूरत के बिना conflicts से बचा जा सकता है और data integrity बनाए रखी जा सकती है।

C और इससे जुड़ी भाषाओं में, thread-local variable घोषित करने के लिए **`__thread`** keyword का उपयोग किया जा सकता है। आपके उदाहरण में यह इस तरह काम करता है:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

यह snippet `tlv_var` को thread-local variable के रूप में परिभाषित करता है। इस कोड को चलाने वाले हर thread का अपना `tlv_var` होगा, और एक thread द्वारा `tlv_var` में किए गए बदलाव दूसरे thread के `tlv_var` को प्रभावित नहीं करेंगे।

Mach-O binary में, thread-local variables से संबंधित data को खास sections में व्यवस्थित किया जाता है:

- **`__DATA.__thread_vars`**: इस section में thread-local variables का metadata होता है, जैसे उनके types और initialization status।
- **`__DATA.__thread_bss`**: इस section का उपयोग उन thread-local variables के लिए किया जाता है जिन्हें स्पष्ट रूप से initialize नहीं किया गया है। यह zero-initialized data के लिए आरक्षित memory का हिस्सा है।

Mach-O, thread के exit होने पर thread-local variables को manage करने के लिए **`tlv_atexit`** नाम का एक खास API भी देता है। यह API आपको **destructors register** करने देता है—ऐसे खास functions जो thread terminate होने पर thread-local data को साफ़ करते हैं।

### Threading प्राथमिकताएँ

Thread priorities को समझने के लिए यह देखना होता है कि operating system threads को कब और कैसे चलाने का निर्णय लेता है। यह निर्णय हर thread को दिए गए priority level से प्रभावित होता है। macOS और Unix-जैसे systems में, इसे `nice`, `renice` और Quality of Service (QoS) classes जैसी अवधारणाओं के ज़रिए संभाला जाता है।

#### Nice और Renice

1. **Nice:**
   - किसी process का `nice` value एक संख्या है जो उसकी priority को प्रभावित करती है। हर process का `nice` value -20 (सबसे अधिक priority) से 19 (सबसे कम priority) तक होता है। Process बनाते समय उसका default `nice` value आम तौर पर 0 होता है।
   - कम `nice` value (जो -20 के अधिक करीब हो) process को ज़्यादा "स्वार्थी" बनाता है, जिससे उसे अधिक `nice` value वाले दूसरे processes की तुलना में ज़्यादा CPU time मिलता है।
2. **Renice:**
   - `renice` एक command है जिसका उपयोग पहले से चल रहे process का `nice` value बदलने के लिए किया जाता है। नए `nice` values के आधार पर processes की CPU time allocation को बढ़ाने या घटाने के लिए उनकी priority को गतिशील रूप से समायोजित किया जा सकता है।
   - उदाहरण के लिए, अगर किसी process को कुछ समय के लिए अधिक CPU resources चाहिए, तो आप `renice` का उपयोग करके उसका `nice` value कम कर सकते हैं।

#### Quality of Service (QoS) Classes

QoS classes, thread priorities को संभालने का अधिक आधुनिक तरीका हैं, खासकर macOS जैसे systems में जो **Grand Central Dispatch (GCD)** को support करते हैं। QoS classes developers को काम को उसकी महत्ता या तात्कालिकता के आधार पर अलग-अलग levels में **वर्गीकृत** करने देती हैं। macOS इन QoS classes के आधार पर thread prioritization को अपने आप manage करता है:

1. **User Interactive:**
   - यह class उन tasks के लिए है जो उस समय user के साथ interact कर रहे हों या जिन्हें अच्छा user experience देने के लिए तुरंत परिणाम चाहिए हों। Interface को responsive बनाए रखने के लिए इन tasks को सबसे अधिक priority दी जाती है (जैसे animations या event handling)।
2. **User Initiated:**
   - ये वे tasks हैं जिन्हें user शुरू करता है और जिनके तुरंत परिणाम की अपेक्षा करता है, जैसे कोई document खोलना या ऐसा button क्लिक करना जिसके लिए computations की ज़रूरत हो। इनकी priority अधिक होती है, लेकिन User Interactive से कम।
3. **Utility:**
   - ये लंबे समय तक चलने वाले tasks हैं जिनमें आम तौर पर progress indicator दिखता है (जैसे files download करना, data import करना)। इनकी priority user-initiated tasks से कम होती है और इन्हें तुरंत पूरा होना ज़रूरी नहीं होता।
4. **Background:**
   - यह class उन tasks के लिए है जो background में चलते हैं और user को दिखाई नहीं देते। इनमें indexing, syncing या backups जैसे tasks शामिल हो सकते हैं। इनकी priority सबसे कम होती है और इनका system performance पर न्यूनतम प्रभाव पड़ता है।

QoS classes का उपयोग करके developers को priority numbers को ठीक-ठीक manage करने की ज़रूरत नहीं होती; वे task के प्रकार पर ध्यान दे सकते हैं और system उसी के अनुसार CPU resources को optimize करता है।

इसके अलावा, अलग-अलग **thread scheduling policies** भी होती हैं जो scheduling parameters का एक set तय करती हैं, जिन्हें scheduler ध्यान में रखता है। यह `thread_policy_[set/get]` का उपयोग करके किया जा सकता है। यह race condition attacks में उपयोगी हो सकता है।

## macOS Process Abuse

macOS, **processes को interact, communicate और data share करने** के लिए कई mechanisms देता है। सामान्य system operation के लिए ये mechanisms आवश्यक हैं, लेकिन attackers इनका दुरुपयोग injection, code execution या data access के लिए कर सकते हैं।

### Library Injection

Library Injection एक ऐसी technique है जिसमें attacker **किसी process को malicious library load करने के लिए बाध्य करता है**। Inject होने के बाद, library target process के context में चलती है, जिससे attacker को process जैसी ही permissions और access मिल जाते हैं।


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking में software code के भीतर **function calls** या messages को intercept किया जाता है। Functions को hook करके attacker process के **व्यवहार को बदल** सकता है, sensitive data देख सकता है या execution flow पर नियंत्रण पा सकता है।


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

यह page ARM64 unwind metadata, arm64e PAC constraints और synthetic call chains को cover करता है।

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) उन अलग-अलग तरीकों को कहते हैं जिनसे अलग processes **data share और exchange** करते हैं। IPC कई वैध applications के लिए मूलभूत है, लेकिन इसका दुरुपयोग process isolation को निष्प्रभावी करने, sensitive information leak करने या unauthorized actions करने के लिए भी किया जा सकता है।


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

कुछ खास env variables के साथ चलने वाले Electron applications process injection के प्रति vulnerable हो सकते हैं:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` और `--use-fake-ui-for-media-stream` flags का उपयोग करके **man in the browser attack** करना संभव है। इससे keystrokes, traffic और cookies चुराए जा सकते हैं, pages में scripts inject की जा सकती हैं...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files किसी application में **user interface (UI) elements और उनके interactions को परिभाषित** करती हैं। हालांकि, वे **arbitrary commands execute कर सकती हैं**, और **NIB file में बदलाव किए जाने पर Gatekeeper पहले से execute हो चुके application को दोबारा execute होने से नहीं रोकता**। इसलिए, इनका उपयोग arbitrary programs से arbitrary commands execute करवाने के लिए किया जा सकता है:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** या **`JDK_JAVA_OPTIONS`** के ज़रिए JVM options inject करना और application शुरू होने से पहले Java या native agent load करना संभव है।


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (file) या `--import data:text/javascript,…` (fileless, Node ≥ 20.6) के ज़रिए attacker का JavaScript पहले से load करता है; **`NODE_REPL_EXTERNAL_MODULE`** किसी module को interactive REPL में load करता है, और **`ELECTRON_RUN_AS_NODE`** Electron binaries पर यह सब फिर से सक्षम करता है।

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` से पहले **`DOTNET_STARTUP_HOOKS`** के ज़रिए .NET applications में code inject करना, या prerequisites मौजूद होने पर .NET debugging functionality का दुरुपयोग करना संभव है।


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash **`BASH_ENV`** पढ़ता है; interactive POSIX shells **`ENV`** पढ़ते हैं; zsh **`$ZDOTDIR/.zshenv`** पढ़ता है; और fish, **`XDG_CONFIG_HOME`** या **`XDG_DATA_DIRS`** के अंतर्गत configuration पढ़ता है। इनमें से हर एक, intended command से पहले नियंत्रित startup file execute कर सकता है। xtrace enabled होने पर (जैसे inherited **`SHELLOPTS=xtrace`** के ज़रिए) Bash, **`PS4`** में रखे command substitution को भी चलाता है:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` शुरू करने पर shell, standard input से program पढ़ता है। इसलिए, जो downloader किसी untrusted structured document को पहले parse किए बिना child के stdin में copy करता है, वह पूरे document को shell source बना देता है। एक देखे गए loader ने एक public iCalendar file को anonymous pipe के ज़रिए line by line भेजा। Calendar metadata commands के रूप में विफल रहा, लेकिन zsh तब तक चलता रहा जब तक उसे `DESCRIPTION:` के बाद रखी executable lines नहीं मिल गईं। उन lines ने अगला application bundle download करके launch किया। Carrier का अपेक्षित content type और trusted hosting इसे सुरक्षित नहीं बनाते; खतरनाक सीमा उसकी bytes को interpreter तक पहुँचाना था।<sup>[[5]](#references)</sup>

संबंधित stages [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md), और [macOS auto-start locations](../../macos-auto-start-locations.md) में cover किए गए हैं।

### PHP Injection

**`PHPRC`** या **`PHP_INI_SCAN_DIR`** के ज़रिए नियंत्रित PHP configuration load की जा सकती है, जिसका **`auto_prepend_file`** target script से पहले execute होता है।

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Standalone Lua interpreter, target script को process करने से पहले **`LUA_INIT`** (या उसके version-specific variant) से code या `@file` execute करता है।

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** और **`R_PROFILE`** उन startup profiles पर redirect करते हैं जिनमें R code होता है। इसके बजाय, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** और R library path के ज़रिए installed package को अपने आप load किया जा सकता है।

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** उस depot पर redirect करता है जिसकी `config/startup.jl` file अपने आप execute होती है।

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** या **`ERL_ZFLAGS`** के ज़रिए payload file की ज़रूरत के बिना Erlang VM में **`-eval`** expression inject किया जा सकता है; Elixir workloads आम तौर पर इसी VM को शुरू करते हैं।

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** और **`OCTAVE_VERSION_INITFILE`** Octave startup scripts पर redirect करते हैं।

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` एक cross-platform .NET app है, इसलिए कई environment variables command से पहले execution की सुविधा देते हैं: **`XDG_CONFIG_HOME`** startup पर चलने वाली profile scripts को redirect करता है, **`PSModulePath`** module auto-loading को hijack करता है (रखी गई `.psm1` file import के समय चलती है और built-in cmdlets की जगह ले सकती है), और .NET के **`CORECLR_PROFILER`**/**`COR_PROFILER`** तथा **`DOTNET_STARTUP_HOOKS`** variables, `Main` से पहले process में attacker का code load करते हैं।

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script से arbitrary code execute करवाने के अलग-अलग विकल्प देखें:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary scripts से arbitrary code execute करवाने के लिए ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) का भी दुरुपयोग किया जा सकता है:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** और **`BROWSER`** की standard-library chain, warning-filter parsing के दौरान command execute कर सकती है। File-backed विकल्प में `sitecustomize.py` को **`PYTHONPATH`** पर रखा जाता है, ताकि सामान्य `site` initialization के दौरान target script से पहले यह import हो जाए। Code के `breakpoint()` तक पहुँचने पर **`PYTHONBREAKPOINT`** चुने गए callable/module को चलाता है। **`PYTHONSTARTUP`** जैसे केवल interactive mode में लागू होने वाले variables का उपयोग सीमित परिस्थितियों में किया जा सकता है।

ध्यान दें कि **`pyinstaller`** से compile किए गए executables इन environmental variables का उपयोग नहीं करेंगे, भले ही वे embedded python के साथ चल रहे हों।

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

सामान्य startup के दौरान **`VIMINIT`** (और उसका `EXINIT` fallback) Ex commands के रूप में execute होते हैं। इसलिए, जब कोई victim नियंत्रित environment के साथ Vim/Neovim खोलता है, तो `:!cmd` / `:call system(...)` code execution दे सकते हैं:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

अलग से, Homebrew अक्सर Python को `/opt/homebrew` के नीचे install करता है, जहाँ local `admin` group के सदस्य launcher को बदलने में सक्षम हो सकते हैं। यह environment-variable injection के बजाय writable-binary hijack है; इसे exploitable मानने से पहले ownership और ACLs जाँचें।


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) एक open-source **EndpointSecurity**-आधारित application है जो process injection का पता लगाती है और उसे block करती है। यह Endpoint Security के ज़रिए देखे जा सकने वाले signals का एक अच्छा संदर्भ है, क्योंकि यह इन पर alert करती है:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec के समय **Injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` और `ELECTRON_RUN_AS_NODE`।
- **`task_for_pid`** calls — एक process द्वारा दूसरे process का task port माँगना, जो उसमें injection करने की पूर्वशर्त है।
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` और `--remote-debugging-port`; ये Electron app को debug mode में शुरू करते हैं और किसी को भी उससे attach होकर code चलाने देते हैं।<sup>[[3]](#references)</sup>
- **अलग-अलग privilege levels के बीच Symlink/hardlink बनाना** — इसका पारंपरिक तरीका है "एक सामान्य user के रूप में link बनाकर उसे किसी privileged location की ओर point करना"। ध्यान दें कि **symlinks पर alert किया जा सकता है, लेकिन उन्हें block नहीं किया जा सकता**: EndpointSecurity, link बनने से पहले उसका destination नहीं दिखाता।

### दूसरे processes द्वारा की गई calls

[**इस blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) में बताया गया है कि दूसरे **process में code inject करने वाले processes** के बारे में जानकारी पाने और फिर उस दूसरे process की जानकारी हासिल करने के लिए **`task_name_for_pid`** function का उपयोग कैसे किया जा सकता है।<sup>[[4]](#references)</sup>

ध्यान दें कि इस function को call करने के लिए आपका **वही uid** होना चाहिए जो process चला रहा है, या फिर **root** होना चाहिए (और यह process के बारे में जानकारी देता है, code inject करने का तरीका नहीं)।

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron apps आपके secrets को गोपनीय रूप से क्यों store नहीं कर सकते: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modifications का पता लगाना](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer का नया version crypto enthusiasts और developers को target करता है](https://securelist.com/macsync-new-version/121383/)
