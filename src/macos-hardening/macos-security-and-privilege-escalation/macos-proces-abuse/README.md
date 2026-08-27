# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

एक process चल रहे executable का instance होता है, हालांकि processes code नहीं चलाते, बल्कि threads चलाते हैं। इसलिए **processes, running threads के लिए केवल containers होते हैं**, जो memory, descriptors, ports, permissions आदि प्रदान करते हैं।

परंपरागत रूप से, processes को (PID 1 को छोड़कर) अन्य processes के भीतर **`fork`** call करके शुरू किया जाता था। यह current process की हूबहू copy बनाता है और फिर **child process** सामान्यतः नए executable को load करके चलाने के लिए **`execve`** call करता था। इसके बाद, बिना memory copying के इस प्रक्रिया को तेज करने के लिए **`vfork`** पेश किया गया।\
फिर **`posix_spawn`** पेश किया गया, जो **`vfork`** और **`execve`** को एक call में संयोजित करता है और flags स्वीकार करता है:

- `POSIX_SPAWN_RESETIDS`: effective ids को real ids पर reset करें
- `POSIX_SPAWN_SETPGROUP`: process group affiliation सेट करें
- `POSUX_SPAWN_SETSIGDEF`: signal का default behaviour सेट करें
- `POSIX_SPAWN_SETSIGMASK`: signal mask सेट करें
- `POSIX_SPAWN_SETEXEC`: उसी process में Exec करें (अधिक options के साथ `execve` की तरह)
- `POSIX_SPAWN_START_SUSPENDED`: suspended स्थिति में शुरू करें
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR के बिना शुरू करें
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc के Nano allocator का उपयोग करें
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segments पर `rwx` की अनुमति दें
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: डिफ़ॉल्ट रूप से exec(2) पर सभी file descriptions बंद करें
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide के high bits को randomize करें

इसके अलावा, `posix_spawn` **`posix_spawnattr`** settings स्वीकार करता है, जो spawned process के aspects को नियंत्रित करती हैं, और **`posix_spawn_file_actions`** entries स्वीकार करता है, जो file descriptors को modify करती हैं।

जब कोई process समाप्त होता है, तो वह `SIGCHLD` signal के साथ **return code parent process को भेजता है** (यदि parent समाप्त हो गया हो, तो नया parent PID 1 होता है)। Parent को यह value `wait4()` या `waitid()` call करके प्राप्त करनी होती है और ऐसा होने तक child zombie state में रहता है, जिसमें वह अभी भी listed रहता है लेकिन resources consume नहीं करता।

### PIDs

PIDs, अर्थात process identifiers, एक unique process की पहचान करते हैं। XNU में **PIDs** **64bits** के होते हैं, monotonic रूप से बढ़ते हैं और **कभी wrap नहीं होते** (abuses से बचने के लिए)।

### Process Groups, Sessions & Coalations

**Processes** को groups में रखा जा सकता है, ताकि उन्हें handle करना आसान हो। उदाहरण के लिए, shell script में commands एक ही process group में होते हैं, इसलिए उन्हें kill का उपयोग करके, उदाहरण के लिए, **एक साथ signal** किया जा सकता है।\
Processes को **sessions में group** करना भी संभव है। जब कोई process session शुरू करता है (`setsid(2)`), तो child processes उस session के भीतर रखे जाते हैं, जब तक कि वे अपनी session शुरू न करें।

Coalition, Darwin में processes को group करने का एक अन्य तरीका है। किसी process का coalition में शामिल होना उसे pool resources तक access करने, ledger share करने या Jetsam का सामना करने की अनुमति देता है। Coalitions की अलग-अलग roles होती हैं: Leader, XPC service, Extension।

### Credentials & Personae

प्रत्येक process के पास **credentials** होती हैं, जो system में उसके **privileges की पहचान करती हैं**। प्रत्येक process के पास एक primary `uid` और एक primary `gid` होगा (हालांकि वह कई groups का सदस्य हो सकता है)।\
यदि binary में `setuid/setgid` bit हो, तो user और group id को बदलना भी संभव है।\
**नए uids/gids सेट** करने के लिए कई functions उपलब्ध हैं।

**`persona`** syscall **credentials** का एक **alternate** set प्रदान करता है। Persona को अपनाने पर उसके uid, gid और group memberships **एक साथ** अपना लिए जाते हैं। [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) में struct देखना संभव है:
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
## Threads की मूल जानकारी

1. **POSIX Threads (pthreads):** macOS POSIX threads (`pthreads`) को support करता है, जो C/C++ के लिए standard threading API का हिस्सा हैं। macOS में pthreads का implementation `/usr/lib/system/libsystem_pthread.dylib` में पाया जाता है, जो सार्वजनिक रूप से उपलब्ध `libpthread` project से आता है। यह library threads को create और manage करने के लिए आवश्यक functions प्रदान करती है।
2. **Creating Threads:** नए threads create करने के लिए `pthread_create()` function का उपयोग किया जाता है। आंतरिक रूप से, यह function `bsdthread_create()` को call करता है, जो XNU kernel (वह kernel जिस पर macOS आधारित है) के लिए specific lower-level system call है। यह system call `pthread_attr` (attributes) से प्राप्त विभिन्न flags लेता है, जो scheduling policies और stack size सहित thread behavior को specify करते हैं।
- **Default Stack Size:** नए threads के लिए default stack size 512 KB है, जो सामान्य operations के लिए पर्याप्त है, लेकिन अधिक या कम space की आवश्यकता होने पर इसे thread attributes के माध्यम से adjust किया जा सकता है।
3. **Thread Initialization:** `__pthread_init()` function thread setup के दौरान महत्वपूर्ण होता है। यह `env[]` argument का उपयोग करके environment variables को parse करता है, जिनमें stack की location और size से संबंधित details शामिल हो सकती हैं।

#### macOS में Thread Termination

1. **Exiting Threads:** Threads को आमतौर पर `pthread_exit()` call करके terminate किया जाता है। यह function thread को cleanly exit करने, आवश्यक cleanup करने और किसी भी joiners को return value भेजने की अनुमति देता है।
2. **Thread Cleanup:** `pthread_exit()` call करने पर `pthread_terminate()` function invoke होता है, जो सभी associated thread structures को remove करता है। यह Mach thread ports (Mach, XNU kernel का communication subsystem है) को deallocate करता है और `bsdthread_terminate` को call करता है, जो thread से associated kernel-level structures को remove करने वाला syscall है।

#### Synchronization Mechanisms

Shared resources तक access manage करने और race conditions से बचने के लिए macOS कई synchronization primitives प्रदान करता है। Multi-threading environments में data integrity और system stability सुनिश्चित करने के लिए ये महत्वपूर्ण हैं:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standard mutex, जिसका memory footprint 60 bytes है (mutex के लिए 56 bytes और signature के लिए 4 bytes)।
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex के समान, लेकिन faster operations के लिए optimized; इसका size भी 60 bytes है।
2. **Condition Variables:**
- कुछ conditions के घटित होने की प्रतीक्षा करने के लिए उपयोग किए जाते हैं; इनका size 44 bytes है (40 bytes और 4-byte signature)।
- **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables के configuration attributes, जिनका size 12 bytes है।
3. **Once Variable (Signature: 0x4f4e4345):**
- यह सुनिश्चित करता है कि initialization code का कोई भाग केवल एक बार execute हो। इसका size 12 bytes है।
4. **Read-Write Locks:**
- एक समय में कई readers या एक writer की अनुमति देता है, जिससे shared data तक efficient access संभव होता है।
- **Read Write Lock (Signature: 0x52574c4b):** इसका size 196 bytes है।
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks के attributes, जिनका size 20 bytes है।

> [!TIP]
> इन objects के अंतिम 4 bytes का उपयोग overflows का पता लगाने के लिए किया जाता है।

### Thread Local Variables (TLV)

Mach-O files (macOS में executables का format) के context में **Thread Local Variables (TLV)** का उपयोग उन variables को declare करने के लिए किया जाता है जो multi-threaded application में **प्रत्येक thread** के लिए specific होते हैं। इससे प्रत्येक thread को किसी variable का अपना अलग instance मिलता है, जिससे mutexes जैसे explicit synchronization mechanisms की आवश्यकता के बिना conflicts से बचने और data integrity बनाए रखने का तरीका मिलता है।

C और संबंधित languages में, आप **`__thread`** keyword का उपयोग करके thread-local variable declare कर सकते हैं। आपके example में यह इस प्रकार काम करता है:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
यह snippet `tlv_var` को एक thread-local variable के रूप में परिभाषित करता है। इस code को चलाने वाले प्रत्येक thread के पास अपना अलग `tlv_var` होगा, और एक thread द्वारा `tlv_var` में किए गए बदलाव किसी अन्य thread के `tlv_var` को प्रभावित नहीं करेंगे।

Mach-O binary में, thread local variables से संबंधित data को विशिष्ट sections में व्यवस्थित किया जाता है:

- **`__DATA.__thread_vars`**: इस section में thread-local variables से संबंधित metadata होता है, जैसे उनके types और initialization status।
- **`__DATA.__thread_bss`**: इस section का उपयोग उन thread-local variables के लिए किया जाता है जिन्हें स्पष्ट रूप से initialize नहीं किया गया है। यह memory का वह भाग है जो zero-initialized data के लिए अलग रखा जाता है।

Mach-O thread के exit होने पर thread-local variables को manage करने के लिए **`tlv_atexit`** नामक एक specific API भी प्रदान करता है। यह API आपको **destructors register** करने देता है—ये special functions thread terminate होने पर thread-local data को clean up करते हैं।

### Threading Priorities

Thread priorities को समझने के लिए यह देखना आवश्यक है कि operating system यह कैसे तय करता है कि कौन से threads चलाने हैं और कब चलाने हैं। यह निर्णय प्रत्येक thread को दिए गए priority level से प्रभावित होता है। macOS और Unix-like systems में इसे `nice`, `renice` और Quality of Service (QoS) classes जैसी concepts का उपयोग करके handle किया जाता है।

#### Nice और Renice

1. **Nice:**
- किसी process का `nice` value एक ऐसी संख्या है जो उसकी priority को प्रभावित करती है। प्रत्येक process का nice value -20 (सबसे high priority) से 19 (सबसे low priority) तक होता है। Process बनाए जाने पर default nice value आमतौर पर 0 होती है।
- कम nice value (जो -20 के करीब हो) किसी process को अधिक "selfish" बनाती है, जिससे उसे अधिक nice values वाले अन्य processes की तुलना में अधिक CPU time मिलता है।
2. **Renice:**
- `renice` पहले से चल रहे process का nice value बदलने के लिए उपयोग की जाने वाली command है। इसका उपयोग processes की priority को dynamically adjust करने के लिए किया जा सकता है, जिसमें नए nice values के आधार पर उनके CPU time allocation को बढ़ाया या घटाया जाता है।
- उदाहरण के लिए, यदि किसी process को अस्थायी रूप से अधिक CPU resources की आवश्यकता हो, तो आप `renice` का उपयोग करके उसका nice value कम कर सकते हैं।

#### Quality of Service (QoS) Classes

QoS classes thread priorities को handle करने का अधिक modern तरीका हैं, विशेष रूप से macOS जैसे systems में जो **Grand Central Dispatch (GCD)** को support करते हैं। QoS classes developers को work को उसकी importance या urgency के आधार पर अलग-अलग levels में **categorize** करने देती हैं। macOS इन QoS classes के आधार पर thread prioritization को automatically manage करता है:

1. **User Interactive:**
- यह class उन tasks के लिए है जो वर्तमान में user के साथ interact कर रहे हैं या अच्छे user experience के लिए immediate results की आवश्यकता रखते हैं। Interface को responsive बनाए रखने के लिए इन tasks को highest priority दी जाती है (जैसे animations या event handling)।
2. **User Initiated:**
- ऐसे tasks जिन्हें user initiate करता है और जिनके immediate results की अपेक्षा होती है, जैसे document खोलना या ऐसा button click करना जिसमें computations की आवश्यकता हो। इनकी priority high होती है, लेकिन user interactive से कम।
3. **Utility:**
- ये tasks लंबे समय तक चलते हैं और आमतौर पर progress indicator दिखाते हैं (जैसे files download करना या data import करना)। इनकी priority user-initiated tasks से कम होती है और इन्हें तुरंत पूरा करना आवश्यक नहीं होता।
4. **Background:**
- यह class background में चलने वाले और user को दिखाई न देने वाले tasks के लिए है। इनमें indexing, syncing या backups जैसे tasks शामिल हो सकते हैं। इनकी priority सबसे कम होती है और system performance पर इनका प्रभाव न्यूनतम होता है।

QoS classes का उपयोग करके developers को exact priority numbers manage करने की आवश्यकता नहीं होती, बल्कि वे task की nature पर ध्यान केंद्रित कर सकते हैं और system उसी के अनुसार CPU resources को optimize करता है।

इसके अतिरिक्त, अलग-अलग **thread scheduling policies** होती हैं जो scheduling parameters का एक set निर्दिष्ट करती हैं, जिन पर scheduler विचार करेगा। यह `thread_policy_[set/get]` का उपयोग करके किया जा सकता है। यह race condition attacks में उपयोगी हो सकता है।

## macOS Process Abuse

macOS processes को **interact, communicate और data share** करने के लिए कई mechanisms प्रदान करता है। हालांकि ये mechanisms normal system operation के लिए आवश्यक हैं, attackers इनका injection, code execution या data access के लिए abuse कर सकते हैं।

### Library Injection

Library Injection एक ऐसी technique है जिसमें attacker **किसी process को malicious library load करने के लिए force करता है**। Inject होने के बाद library target process के context में चलती है, जिससे attacker को उस process जैसी ही permissions और access मिल जाते हैं।


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking में software code के भीतर **function calls** या messages को **intercept** किया जाता है। Functions को hook करके attacker किसी process के **behavior को modify** कर सकता है, sensitive data observe कर सकता है या execution flow पर control भी प्राप्त कर सकता है।


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) उन अलग-अलग methods को संदर्भित करता है जिनके द्वारा separate processes **data share और exchange** करते हैं। हालांकि IPC कई legitimate applications के लिए fundamental है, इसका दुरुपयोग process isolation को subvert करने, sensitive information को leak करने या unauthorized actions perform करने के लिए भी किया जा सकता है।


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Specific env variables के साथ execute की गई Electron applications process injection के प्रति vulnerable हो सकती हैं:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` और `--use-fake-ui-for-media-stream` flags का उपयोग करके **man in the browser attack** करना संभव है, जिससे keystrokes और traffic steal किए जा सकते हैं, cookies चुराई जा सकती हैं और pages में scripts inject की जा सकती हैं...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files किसी application के भीतर **user interface (UI) elements** और उनके interactions को **define** करती हैं। हालांकि, वे **arbitrary commands execute** कर सकती हैं और यदि किसी **NIB file को modify** किया गया हो, तो **Gatekeeper पहले से execute हो चुकी application को दोबारा execute होने से नहीं रोकता**। इसलिए, इनका उपयोग arbitrary programs से arbitrary commands execute करवाने के लिए किया जा सकता है:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** या **`JDK_JAVA_OPTIONS`** के माध्यम से JVM options inject करना और application start होने से पहले Java या native agent load करना संभव है।


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

`Main` से पहले **`DOTNET_STARTUP_HOOKS`** के माध्यम से .NET applications में code inject करना संभव है। इसके अतिरिक्त, prerequisites मौजूद होने पर .NET debugging functionality का abuse किया जा सकता है।


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash **`BASH_ENV`** पढ़ता है; zsh **`$ZDOTDIR/.zshenv`** पढ़ता है; और fish **`XDG_CONFIG_HOME`** या **`XDG_DATA_DIRS`** के नीचे configuration पढ़ता है। इनमें से प्रत्येक intended command से पहले एक controlled startup file execute कर सकता है:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** या **`PHP_INI_SCAN_DIR`** controlled PHP configuration load कर सकते हैं, जिसका **`auto_prepend_file`** target script से पहले execute होता है।

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Standalone Lua interpreter target script को process करने से पहले **`LUA_INIT`** (या उसके version-specific variant) से code या `@file` execute करता है।

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** और **`R_PROFILE`** startup profiles को redirect करते हैं जिनमें R code होता है। **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** और R library path के साथ किसी installed package को इसके बजाय automatically load किया जा सकता है।

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** उस depot को redirect करता है जिसकी `config/startup.jl` automatically execute होती है।

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** या **`ERL_ZFLAGS`** payload file की आवश्यकता के बिना Erlang VM में **`-eval`** expression inject कर सकते हैं; Elixir workloads आमतौर पर इसी VM को start करते हैं।

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** और **`OCTAVE_VERSION_INITFILE`** Octave startup scripts को redirect करते हैं।

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

macOS और Linux पर, **`XDG_CONFIG_HOME`** उन PowerShell user profiles को redirect कर सकता है जो `pwsh` start होने पर execute होती हैं।

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script से arbitrary code execute करवाने के लिए अलग-अलग options देखें:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby env variables का abuse करके arbitrary scripts से arbitrary code execute करवाना भी संभव है:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** और **`BROWSER`** standard-library chain warning-filter parsing के दौरान command execute कर सकती है। File-backed alternative में **`PYTHONPATH`** पर `sitecustomize.py` रखा जाता है, ताकि normal `site` initialization target script से पहले उसे import कर ले। Interactive-only variables जैसे **`PYTHONSTARTUP`** का applicability scope अधिक सीमित होता है।

ध्यान दें कि **`pyinstaller`** से compiled executables इन environmental variables का उपयोग नहीं करेंगे, भले ही वे embedded python के साथ चल रहे हों।

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

अलग से, Homebrew आमतौर पर Python को `/opt/homebrew` के नीचे install करता है, जहां local `admin` group के members launcher को replace करने में सक्षम हो सकते हैं। यह environment-variable injection के बजाय writable-binary hijack है; इसे exploitable मानने से पहले ownership और ACLs verify करें।


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) एक open-source **EndpointSecurity**-based application है जो process injection को detect और block करती है। यह इस बात के लिए एक अच्छा reference है कि Endpoint Security के माध्यम से कौन से signals observable हैं, क्योंकि यह इन पर alert करती है:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec पर **Injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` और `ELECTRON_RUN_AS_NODE`।
- **`task_for_pid`** calls — एक process द्वारा दूसरे process का task port मांगना, जो उसमें injection करने के लिए prerequisite है।
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` और `--remote-debugging-port`, जो Electron app को debug mode में start करते हैं और किसी को भी उसमें attach होकर code run करने देते हैं।<sup>[[3]](#references)</sup>
- **Privilege levels के बीच Symlink/hardlink creation** — classic primitive: "एक normal user के रूप में link बनाएं और उसे किसी privileged location की ओर point करें।" ध्यान दें कि **symlinks पर alert किया जा सकता है, लेकिन उन्हें block नहीं किया जा सकता**: EndpointSecurity creation से पहले link destination expose नहीं करता।

### Calls made by other processes

[**इस blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) में आप जान सकते हैं कि **`task_name_for_pid`** function का उपयोग करके किसी process में code inject करने वाले अन्य **processes** के बारे में information प्राप्त करना और फिर उस दूसरे process के बारे में information प्राप्त करना कैसे संभव है।<sup>[[4]](#references)</sup>

ध्यान दें कि उस function को call करने के लिए आपका uid उस process को run करने वाले uid के **समान** होना चाहिए या आपके पास **root** access होना चाहिए (और यह process के बारे में information return करता है, code inject करने का तरीका नहीं)।

## References

- [1] [Shield — open-source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
