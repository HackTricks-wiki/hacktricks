# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes की बुनियादी जानकारी

Process, चल रहे executable का एक instance होता है। हालांकि, processes code नहीं चलाते; ये threads होते हैं। इसलिए **processes, running threads के लिए केवल containers होते हैं**, जो memory, descriptors, ports, permissions आदि उपलब्ध कराते हैं।

परंपरागत रूप से, processes अन्य processes (PID 1 को छोड़कर) के भीतर **`fork`** call करके शुरू किए जाते थे। इससे मौजूदा process की एक सटीक copy बनती थी और फिर **child process** आम तौर पर नया executable load करके उसे चलाने के लिए **`execve`** call करता था। इसके बाद, बिना memory copy किए इस प्रक्रिया को तेज़ करने के लिए **`vfork`** पेश किया गया।\
फिर **`posix_spawn`** पेश किया गया, जो **`vfork`** और **`execve`** को एक call में जोड़ता है और flags स्वीकार करता है:

- `POSIX_SPAWN_RESETIDS`: effective ids को real ids पर reset करें
- `POSIX_SPAWN_SETPGROUP`: process group affiliation सेट करें
- `POSUX_SPAWN_SETSIGDEF`: signal का default behaviour सेट करें
- `POSIX_SPAWN_SETSIGMASK`: signal mask सेट करें
- `POSIX_SPAWN_SETEXEC`: उसी process में exec करें (`execve` की तरह, लेकिन अधिक options के साथ)
- `POSIX_SPAWN_START_SUSPENDED`: suspended स्थिति में शुरू करें
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR के बिना शुरू करें
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc का Nano allocator इस्तेमाल करें
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segments पर `rwx` की अनुमति दें
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: डिफ़ॉल्ट रूप से exec(2) पर सभी file descriptions बंद करें
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide के high bits को randomize करें

इसके अलावा, `posix_spawn` **`posix_spawnattr`** settings स्वीकार करता है, जो spawned process के पहलुओं को नियंत्रित करती हैं, और **`posix_spawn_file_actions`** entries स्वीकार करता है, जो file descriptors को संशोधित करती हैं।

जब कोई process समाप्त होता है, तो वह `SIGCHLD` signal के साथ **parent process को return code भेजता है** (यदि parent समाप्त हो चुका हो, तो नया parent PID 1 होता है)। Parent को `wait4()` या `waitid()` call करके यह value प्राप्त करनी होती है। ऐसा होने तक child zombie state में रहता है: वह सूची में दिखता रहता है, लेकिन resources का उपयोग नहीं करता।

### PIDs

PIDs यानी process identifiers, एक अद्वितीय process की पहचान करते हैं। XNU में **PIDs** **64bits** के होते हैं, लगातार बढ़ते हैं और **कभी wrap नहीं होते** (abuses रोकने के लिए)।

### Process Groups, Sessions & Coalations

**Processes** को **groups** में रखा जा सकता है, ताकि उन्हें संभालना आसान हो। उदाहरण के लिए, shell script में commands एक ही process group में होते हैं, इसलिए उन्हें kill का उपयोग करके, जैसे, **एक साथ signal** करना संभव है।\
**Processes को sessions में group** करना भी संभव है। जब कोई process session शुरू करता है (`setsid(2)`), तो उसके child processes उस session में रखे जाते हैं, जब तक कि वे अपना session शुरू न करें।

Darwin में processes को group करने का एक और तरीका Coalition है। Coalition में शामिल होने पर process pool resources तक पहुँच सकता है, ledger साझा कर सकता है या Jetsam का सामना कर सकता है। Coalations की अलग-अलग roles होती हैं: Leader, XPC service, Extension।

### Credentials & Personae

हर process के पास **credentials** होते हैं, जो system में उसके **privileges की पहचान करते हैं**। हर process का एक primary `uid` और एक primary `gid` होता है (हालांकि वह कई groups का सदस्य हो सकता है)।\
यदि binary पर `setuid/setgid` bit लगा हो, तो user और group id बदलना भी संभव है।\
**नए uids/gids सेट करने** के लिए कई functions मौजूद हैं।

Syscall **`persona`** credentials का एक **वैकल्पिक** set उपलब्ध कराता है। Persona अपनाने पर उसके uid, gid और group memberships **एक साथ** लागू होते हैं। [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) में यह struct देखा जा सकता है:

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

1. **POSIX Threads (pthreads):** macOS, POSIX threads (`pthreads`) को सपोर्ट करता है, जो C/C++ के लिए एक मानक threading API का हिस्सा हैं। macOS में pthreads का implementation `/usr/lib/system/libsystem_pthread.dylib` में मिलता है, जो सार्वजनिक रूप से उपलब्ध `libpthread` project से आता है। यह library threads बनाने और प्रबंधित करने के लिए आवश्यक functions देती है।
2. **Threads बनाना:** नए threads बनाने के लिए `pthread_create()` function का उपयोग किया जाता है। अंदरूनी तौर पर, यह function `bsdthread_create()` को call करता है, जो XNU kernel (जिस पर macOS आधारित है) के लिए एक lower-level system call है। यह system call, `pthread_attr` (attributes) से लिए गए कई flags लेता है, जो thread के व्यवहार को निर्दिष्ट करते हैं—जैसे scheduling policies और stack size।
   - **डिफ़ॉल्ट Stack Size:** नए threads का डिफ़ॉल्ट stack size 512 KB होता है। सामान्य operations के लिए यह पर्याप्त है, लेकिन अधिक या कम जगह की ज़रूरत होने पर इसे thread attributes के ज़रिए बदला जा सकता है।
3. **Thread Initialization:** `__pthread_init()` function thread setup के दौरान महत्वपूर्ण होता है। यह `env[]` argument का उपयोग करके environment variables को parse करता है, जिनमें stack की location और size की जानकारी शामिल हो सकती है।

#### macOS में Thread Termination

1. **Threads से बाहर निकलना:** आम तौर पर threads को `pthread_exit()` call करके terminate किया जाता है। यह function thread को साफ़-सुथरे ढंग से बाहर निकलने देता है, ज़रूरी cleanup करता है और thread को join करने वाले किसी भी caller को return value भेजने देता है।
2. **Thread Cleanup:** `pthread_exit()` call होने पर `pthread_terminate()` function invoke होता है, जो thread से जुड़े सभी structures को हटाता है। यह Mach thread ports (Mach, XNU kernel का communication subsystem है) को deallocate करता है और `bsdthread_terminate` नाम का syscall call करता है, जो thread से जुड़े kernel-level structures को हटाता है।

#### Synchronization Mechanisms

Shared resources तक पहुँच को प्रबंधित करने और race conditions से बचने के लिए macOS कई synchronization primitives देता है। Multi-threading environments में data integrity और system stability सुनिश्चित करने के लिए ये ज़रूरी हैं:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** मानक mutex, जिसका memory footprint 60 bytes है (mutex के लिए 56 bytes और signature के लिए 4 bytes)।
   - **Fast Mutex (Signature: 0x4d55545A):** Regular mutex जैसा, लेकिन तेज़ operations के लिए optimized; इसका आकार भी 60 bytes है।
2. **Condition Variables:**
   - कुछ शर्तें पूरी होने की प्रतीक्षा के लिए उपयोग होते हैं। इनका आकार 44 bytes (40 bytes और 4-byte signature) है।
   - **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables के configuration attributes, जिनका आकार 12 bytes है।
3. **Once Variable (Signature: 0x4f4e4345):**
   - यह सुनिश्चित करता है कि initialization code का कोई हिस्सा केवल एक बार execute हो। इसका आकार 12 bytes है।
4. **Read-Write Locks:**
   - एक समय में कई readers या एक writer को अनुमति देते हैं, जिससे shared data तक कुशलतापूर्वक पहुँचा जा सकता है।
   - **Read Write Lock (Signature: 0x52574c4b):** इसका आकार 196 bytes है।
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks के attributes, जिनका आकार 20 bytes है।

> [!TIP]
> इन objects के आखिरी 4 bytes का उपयोग overflows का पता लगाने के लिए किया जाता है।

### Thread Local Variables (TLV)

Mach-O files (macOS में executables का format) के संदर्भ में **Thread Local Variables (TLV)** का उपयोग ऐसी variables घोषित करने के लिए किया जाता है जो multi-threaded application में **हर thread के लिए अलग** हों। इससे हर thread को variable का अपना अलग instance मिलता है। इस तरह, mutexes जैसे explicit synchronization mechanisms की ज़रूरत के बिना conflicts से बचा जा सकता है और data integrity बनाए रखी जा सकती है।

C और इससे संबंधित languages में, **`__thread`** keyword का उपयोग करके thread-local variable घोषित किया जा सकता है। आपके उदाहरण में यह इस तरह काम करता है:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

यह snippet `tlv_var` को thread-local variable के रूप में परिभाषित करता है। इस code को चलाने वाले हर thread का अपना `tlv_var` होगा, और एक thread द्वारा `tlv_var` में किए गए बदलाव दूसरे thread के `tlv_var` को प्रभावित नहीं करेंगे।

Mach-O binary में, thread-local variables से संबंधित data को विशेष sections में व्यवस्थित किया जाता है:

- **`__DATA.__thread_vars`**: इस section में thread-local variables का metadata होता है, जैसे उनके types और initialization status।
- **`__DATA.__thread_bss`**: इस section का उपयोग उन thread-local variables के लिए होता है जिन्हें स्पष्ट रूप से initialize नहीं किया गया है। यह zero-initialized data के लिए अलग रखी गई memory का हिस्सा है।

Mach-O, thread के समाप्त होने पर thread-local variables को manage करने के लिए **`tlv_atexit`** नाम का एक विशेष API भी देता है। इस API से **destructors register** किए जा सकते हैं—ये विशेष functions thread के समाप्त होने पर thread-local data को साफ़ करते हैं।

### थ्रेडिंग प्राथमिकताएँ

Thread priorities को समझने के लिए यह देखना होता है कि operating system कैसे तय करता है कि कौन-से threads कब चलेंगे। यह निर्णय हर thread को दिए गए priority level से प्रभावित होता है। macOS और Unix-जैसे systems में इसे `nice`, `renice` और Quality of Service (QoS) classes जैसी अवधारणाओं के ज़रिए संभाला जाता है।

#### Nice और Renice

1. **Nice:**
   - किसी process का `nice` value एक संख्या है जो उसकी priority को प्रभावित करती है। हर process का nice value -20 (सबसे अधिक priority) से 19 (सबसे कम priority) तक होता है। Process बनाते समय default nice value आम तौर पर 0 होता है।
   - कम nice value (जो -20 के करीब हो) process को अधिक “स्वार्थी” बनाता है, जिससे उसे अधिक nice value वाले दूसरे processes की तुलना में अधिक CPU time मिलता है।
2. **Renice:**
   - `renice` एक command है जिसका उपयोग पहले से चल रहे process का nice value बदलने के लिए किया जाता है। इससे नए nice values के आधार पर processes की priority को गतिशील रूप से बढ़ाया या घटाया जा सकता है, और उनके CPU time allocation को समायोजित किया जा सकता है।
   - उदाहरण के लिए, अगर किसी process को कुछ समय के लिए अधिक CPU resources चाहिए, तो `renice` का उपयोग करके उसका nice value कम किया जा सकता है।

#### Quality of Service (QoS) Classes

QoS classes, thread priorities को संभालने का एक अधिक आधुनिक तरीका हैं—खास तौर पर macOS जैसे systems में, जो **Grand Central Dispatch (GCD)** को support करते हैं। QoS classes से developers काम को उसके महत्व या तात्कालिकता के आधार पर अलग-अलग levels में **वर्गीकृत** कर सकते हैं। macOS इन QoS classes के आधार पर thread prioritization को अपने आप manage करता है:

1. **User Interactive:**
   - यह class उन tasks के लिए है जो इस समय user के साथ interact कर रहे हों या अच्छा user experience देने के लिए तुरंत परिणाम देना ज़रूरी हो। Interface को responsive रखने के लिए इन tasks को सबसे अधिक priority दी जाती है (जैसे animations या event handling)।
2. **User Initiated:**
   - ये वे tasks हैं जिन्हें user शुरू करता है और जिनसे तुरंत परिणाम की अपेक्षा होती है, जैसे कोई document खोलना या ऐसा button क्लिक करना जिसके लिए computations ज़रूरी हों। इनकी priority अधिक होती है, लेकिन User Interactive से कम।
3. **Utility:**
   - ये लंबे समय तक चलने वाले tasks होते हैं और आम तौर पर progress indicator दिखाते हैं (जैसे files download करना या data import करना)। इनकी priority user-initiated tasks से कम होती है और इन्हें तुरंत पूरा करना ज़रूरी नहीं होता।
4. **Background:**
   - यह class उन tasks के लिए है जो background में चलते हैं और user को दिखाई नहीं देते। इनमें indexing, syncing या backups जैसे tasks शामिल हो सकते हैं। इनकी priority सबसे कम होती है और system performance पर इनका असर न्यूनतम होता है।

QoS classes का उपयोग करने से developers को सटीक priority numbers manage करने की ज़रूरत नहीं होती; वे task की प्रकृति पर ध्यान दे सकते हैं और system उसी के अनुसार CPU resources को optimize करता है।

इसके अलावा, अलग-अलग **thread scheduling policies** होती हैं, जो scheduling parameters का एक set तय करने के लिए उपयोग की जाती हैं और जिन्हें scheduler ध्यान में रखता है। यह `thread_policy_[set/get]` का उपयोग करके किया जा सकता है। Race condition attacks में यह उपयोगी हो सकता है।

## macOS Process Abuse

macOS, **processes को interact करने, communicate करने और data share करने** के कई mechanisms देता है। ये mechanisms सामान्य system operation के लिए ज़रूरी हैं, लेकिन attackers इनका दुरुपयोग injection, code execution या data access के लिए कर सकते हैं।

### Library Injection

Library Injection एक ऐसी technique है जिसमें attacker **किसी process को malicious library load करने के लिए मजबूर करता है**। Inject होने के बाद, library target process के context में चलती है और attacker को process जैसी ही permissions और access देती है।


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking में software code के भीतर **function calls** या messages को intercept किया जाता है। Functions को hook करके attacker किसी process का **व्यवहार बदल सकता है**, sensitive data देख सकता है, या execution flow पर नियंत्रण भी हासिल कर सकता है।


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) उन अलग-अलग तरीकों को कहते हैं जिनसे अलग-अलग processes **data share और exchange करते हैं**। IPC कई वैध applications के लिए बुनियादी है, लेकिन इसका दुरुपयोग process isolation को दरकिनार करने, संवेदनशील जानकारी leak करने या अनधिकृत कार्रवाइयाँ करने के लिए भी किया जा सकता है।


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

विशेष env variables के साथ चलाए गए Electron applications process injection के प्रति असुरक्षित हो सकते हैं:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` और `--use-fake-ui-for-media-stream` flags का उपयोग करके **man in the browser attack** करना संभव है। इससे keystrokes और traffic चुराए जा सकते हैं, cookies हासिल की जा सकती हैं, pages में scripts inject की जा सकती हैं...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files किसी application के भीतर **user interface (UI) elements और उनके interactions को परिभाषित करती हैं**। हालांकि, ये **arbitrary commands चला सकती हैं**, और अगर **NIB file में बदलाव किया गया हो**, तो Gatekeeper पहले से execute हो चुके application को दोबारा execute होने से नहीं रोकता। इसलिए, इनका उपयोग arbitrary programs से arbitrary commands चलवाने के लिए किया जा सकता है:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** या **`JDK_JAVA_OPTIONS`** के ज़रिए JVM options inject करना और application शुरू होने से पहले Java या native agent load करना संभव है।


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** के ज़रिए attacker का JavaScript `--require` (file) या `--import data:text/javascript,…` (fileless, Node ≥ 20.6) से preload किया जा सकता है; **`NODE_REPL_EXTERNAL_MODULE`** किसी module को interactive REPL में load करता है, और **`ELECTRON_RUN_AS_NODE`** Electron binaries पर इन सभी सुविधाओं को फिर से enable करता है।

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` चलने से पहले **`DOTNET_STARTUP_HOOKS`** के ज़रिए .NET applications में code inject करना संभव है। इसके अलावा, prerequisites मौजूद होने पर .NET debugging functionality का दुरुपयोग भी किया जा सकता है।


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash, **`BASH_ENV`** पढ़ता है; interactive POSIX shells, **`ENV`** पढ़ते हैं; zsh, **`$ZDOTDIR/.zshenv`** पढ़ता है; और fish, **`XDG_CONFIG_HOME`** या **`XDG_DATA_DIRS`** के नीचे से configuration पढ़ता है। हर एक, इच्छित command से पहले नियंत्रित startup file चला सकता है। xtrace enable होने पर Bash, **`PS4`** में रखे command substitution को भी चलाता है (उदाहरण के लिए, inherited **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** या **`PHP_INI_SCAN_DIR`** से नियंत्रित PHP configuration load की जा सकती है, जिसमें **`auto_prepend_file`** target script से पहले execute होती है।

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Standalone Lua interpreter, target script को process करने से पहले **`LUA_INIT`** (या उसके version-specific variant) से code या `@file` execute करता है।

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** और **`R_PROFILE`** को बदलकर R code वाली startup profiles को redirect किया जा सकता है। इसके बजाय, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** और R library path का उपयोग करके किसी installed package को अपने आप load किया जा सकता है।

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** उस depot को redirect करता है जिसका `config/startup.jl` अपने आप execute होता है।

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** या **`ERL_ZFLAGS`** से payload file की ज़रूरत के बिना Erlang VM में **`-eval`** expression inject किया जा सकता है; Elixir workloads भी आम तौर पर यही VM शुरू करते हैं।

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** और **`OCTAVE_VERSION_INITFILE`** से Octave startup scripts को redirect किया जा सकता है।

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` एक cross-platform .NET app है, इसलिए कई environment variables command चलने से पहले code execution करा सकते हैं: **`XDG_CONFIG_HOME`** startup पर चलने वाली profile scripts को redirect करता है, **`PSModulePath`** module auto-loading को hijack करता है (रखी गई `.psm1` file import के समय चलती है और built-in cmdlets की जगह ले सकती है), और .NET के **`CORECLR_PROFILER`**/**`COR_PROFILER`** तथा **`DOTNET_STARTUP_HOOKS`** variables `Main` से पहले process में attacker code load करते हैं।

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script से arbitrary code execute करवाने के अलग-अलग तरीकों के बारे में जानें:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary scripts से arbitrary code execute करवाने के लिए Ruby env variables (**`RUBYOPT`**, **`RUBYLIB`**) का दुरुपयोग भी किया जा सकता है:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** और **`BROWSER`** की standard-library chain, warning-filter parsing के दौरान command execute कर सकती है। File-backed विकल्प के तौर पर **`PYTHONPATH`** पर `sitecustomize.py` रखा जा सकता है, ताकि सामान्य `site` initialization target script से पहले उसे import करे। Code के `breakpoint()` तक पहुँचने पर **`PYTHONBREAKPOINT`** चुने गए callable/module को चलाता है। **`PYTHONSTARTUP`** जैसे केवल interactive mode में काम करने वाले variables का उपयोग सीमित है।

ध्यान दें कि **`pyinstaller`** से compile किए गए executables, embedded Python का उपयोग करके चलने पर भी इन environmental variables का उपयोग नहीं करेंगे।

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

सामान्य startup पर **`VIMINIT`** (और उसका `EXINIT` fallback) Ex commands के रूप में execute होते हैं। इसलिए, जब victim नियंत्रित environment के साथ Vim/Neovim खोलता है, तो `:!cmd` / `:call system(...)` से code execution हो सकता है:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

अलग से, Homebrew आम तौर पर Python को `/opt/homebrew` के नीचे install करता है, जहाँ local `admin` group के सदस्य launcher को बदलने में सक्षम हो सकते हैं। यह environment-variable injection के बजाय writable-binary hijack है; इसे exploitable मानने से पहले ownership और ACLs की जाँच करें।


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) एक open-source **EndpointSecurity**-आधारित application है, जो process injection को detect और block करता है। यह इस बात का अच्छा संदर्भ है कि Endpoint Security के ज़रिए कौन-से signals देखे जा सकते हैं, क्योंकि यह इन पर alert करता है:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec पर **Injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` और `ELECTRON_RUN_AS_NODE`।
- **`task_for_pid`** calls — एक process द्वारा दूसरे process का task port माँगना, जो उसमें injection करने की पूर्वशर्त है।
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` और `--remote-debugging-port`; ये Electron app को debug mode में शुरू करते हैं और किसी को भी उसमें attach होकर code चलाने देते हैं।<sup>[[3]](#references)</sup>
- **अलग-अलग privilege levels पर symlink/hardlink बनाना** — सामान्य user के रूप में link बनाकर उसे किसी privileged location की ओर point करने का पारंपरिक तरीका। ध्यान दें कि **symlinks पर alert किया जा सकता है, लेकिन उन्हें block नहीं किया जा सकता**: EndpointSecurity, link बनने से पहले उसका destination उपलब्ध नहीं कराता।

### दूसरे processes द्वारा की गई calls

[**इस blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) में बताया गया है कि किसी process में code inject कर रहे दूसरे **processes** के बारे में जानकारी पाने के लिए **`task_name_for_pid`** function का उपयोग कैसे किया जा सकता है, और फिर उस दूसरे process के बारे में जानकारी कैसे हासिल की जा सकती है।<sup>[[4]](#references)</sup>

ध्यान दें कि इस function को call करने के लिए आपका uid, process चलाने वाले uid जैसा होना चाहिए या आपके पास **root** access होना चाहिए (और यह process के बारे में जानकारी देता है, code inject करने का तरीका नहीं)।

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
