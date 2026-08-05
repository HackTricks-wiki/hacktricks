# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

एक process चल रहे executable का एक instance होता है, हालांकि processes code नहीं चलाते, बल्कि ये threads होते हैं। इसलिए **processes running threads के लिए केवल containers होते हैं**, जो memory, descriptors, ports, permissions आदि प्रदान करते हैं।

परंपरागत रूप से, processes को PID 1 को छोड़कर, अन्य processes के भीतर **`fork`** कॉल करके शुरू किया जाता था। यह current process की एक exact copy बनाता था और फिर **child process** सामान्यतः नए executable को load करके चलाने के लिए **`execve`** कॉल करता था। इसके बाद, बिना किसी memory copying के इस process को तेज़ बनाने के लिए **`vfork`** प्रस्तुत किया गया।\
फिर **`posix_spawn`** प्रस्तुत किया गया, जो **`vfork`** और **`execve`** को एक ही call में जोड़ता है और flags स्वीकार करता है:

- `POSIX_SPAWN_RESETIDS`: effective ids को real ids पर reset करें
- `POSIX_SPAWN_SETPGROUP`: process group affiliation सेट करें
- `POSUX_SPAWN_SETSIGDEF`: signal का default behaviour सेट करें
- `POSIX_SPAWN_SETSIGMASK`: signal mask सेट करें
- `POSIX_SPAWN_SETEXEC`: उसी process में Exec करें (`execve` की तरह, लेकिन अधिक options के साथ)
- `POSIX_SPAWN_START_SUSPENDED`: suspended स्थिति में शुरू करें
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR के बिना शुरू करें
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc के Nano allocator का उपयोग करें
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segments पर `rwx` की अनुमति दें
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: डिफ़ॉल्ट रूप से exec(2) पर सभी file descriptions बंद करें
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide के high bits को randomize करें

इसके अलावा, `posix_spawn` **`posix_spawnattr`** की एक array निर्दिष्ट करने की अनुमति देता है, जो spawned process के कुछ aspects को नियंत्रित करती है, और descriptors की state को modify करने के लिए **`posix_spawn_file_actions`** का उपयोग किया जा सकता है।

जब कोई process समाप्त होता है, तो वह `SIGCHLD` signal के साथ **return code parent process को भेजता है** (यदि parent समाप्त हो गया हो, तो नया parent PID 1 होता है)। Parent को `wait4()` या `waitid()` कॉल करके यह value प्राप्त करनी होती है। ऐसा होने तक child zombie state में रहता है, जिसमें वह अभी भी listed होता है, लेकिन resources consume नहीं करता।

### PIDs

PIDs, अर्थात process identifiers, एक unique process की पहचान करते हैं। XNU में **PIDs** 64bits के होते हैं, monotonically बढ़ते हैं और **कभी wrap नहीं होते** (abuses को रोकने के लिए)।

### Process Groups, Sessions & Coalations

**Processes** को groups में insert किया जा सकता है, ताकि उन्हें handle करना आसान हो। उदाहरण के लिए, shell script में commands एक ही process group में होती हैं, इसलिए उन्हें kill का उपयोग करके, उदाहरण के लिए, **एक साथ signal** करना संभव होता है।\
Processes को **sessions में group** करना भी संभव है। जब कोई process एक session (`setsid(2)`) शुरू करता है, तो child processes उस session के भीतर सेट किए जाते हैं, जब तक कि वे अपनी स्वयं की session शुरू न करें।

Coalition Darwin में processes को group करने का एक अन्य तरीका है। किसी process का coalition में शामिल होना उसे pool resources तक access करने, ledger share करने या Jetsam का सामना करने की अनुमति देता है। Coalitions की अलग-अलग roles होती हैं: Leader, XPC service, Extension।

### Credentials & Personae

प्रत्येक process के पास **credentials** होते हैं, जो system में उसके **privileges की पहचान करते हैं**। प्रत्येक process के पास एक primary `uid` और एक primary `gid` होता है (हालांकि वह कई groups का सदस्य हो सकता है)।\
यदि binary में `setuid/setgid` bit हो, तो user और group id को बदलना भी संभव है।\
**नए uids/gids सेट करने** के लिए कई functions उपलब्ध हैं।

**`persona`** syscall **credentials** का एक **alternate** set प्रदान करता है। Persona को adopt करने पर उसके uid, gid और group memberships **एक साथ** अपना लिए जाते हैं। [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) में struct को देखा जा सकता है:
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

1. **POSIX Threads (pthreads):** macOS POSIX threads (`pthreads`) को support करता है, जो C/C++ के लिए standard threading API का हिस्सा हैं। macOS में pthreads का implementation `/usr/lib/system/libsystem_pthread.dylib` में पाया जाता है, जो publicly available `libpthread` project से आता है। यह library threads को create और manage करने के लिए आवश्यक functions प्रदान करती है।
2. **Creating Threads:** नए threads create करने के लिए `pthread_create()` function का उपयोग किया जाता है। आंतरिक रूप से, यह function `bsdthread_create()` को call करता है, जो XNU kernel (वह kernel जिस पर macOS आधारित है) के लिए specific lower-level system call है। यह system call `pthread_attr` (attributes) से प्राप्त विभिन्न flags लेता है, जो thread behavior, including scheduling policies और stack size, specify करते हैं।
- **Default Stack Size:** नए threads के लिए default stack size 512 KB है, जो typical operations के लिए पर्याप्त है, लेकिन अधिक या कम space की आवश्यकता होने पर इसे thread attributes के माध्यम से adjust किया जा सकता है।
3. **Thread Initialization:** `__pthread_init()` function thread setup के दौरान महत्वपूर्ण है। यह `env[]` argument का उपयोग करके environment variables को parse करता है, जिनमें stack के location और size से संबंधित details शामिल हो सकती हैं।

#### macOS में Thread Termination

1. **Exiting Threads:** Threads को आमतौर पर `pthread_exit()` call करके terminate किया जाता है। यह function किसी thread को cleanly exit करने, आवश्यक cleanup करने और किसी भी joiners को return value भेजने की अनुमति देता है।
2. **Thread Cleanup:** `pthread_exit()` call करने पर `pthread_terminate()` function invoke होता है, जो सभी associated thread structures को remove करने का काम करता है। यह Mach thread ports को deallocate करता है (Mach, XNU kernel का communication subsystem है) और `bsdthread_terminate` को call करता है, जो thread से associated kernel-level structures को remove करने वाला syscall है।

#### Synchronization Mechanisms

Shared resources तक access manage करने और race conditions से बचने के लिए macOS कई synchronization primitives प्रदान करता है। Multi-threading environments में data integrity और system stability सुनिश्चित करने के लिए ये महत्वपूर्ण हैं:

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** Standard mutex, जिसका memory footprint 60 bytes है (mutex के लिए 56 bytes और signature के लिए 4 bytes)।
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex के समान, लेकिन faster operations के लिए optimized; इसका size भी 60 bytes है।
2. **Condition Variables:**
- कुछ conditions के occur होने की प्रतीक्षा करने के लिए उपयोग किए जाते हैं। इनका size 44 bytes है (40 bytes और 4-byte signature)।
- **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables के configuration attributes, जिनका size 12 bytes है।
3. **Once Variable (Signature: 0x4f4e4345):**
- सुनिश्चित करता है कि initialization code का कोई piece केवल एक बार execute हो। इसका size 12 bytes है।
4. **Read-Write Locks:**
- एक समय में multiple readers या एक writer की अनुमति देता है, जिससे shared data तक efficient access संभव होता है।
- **Read Write Lock (Signature: 0x52574c4b):** इसका size 196 bytes है।
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write locks के attributes, जिनका size 20 bytes है।

> [!TIP]
> इन objects के अंतिम 4 bytes overflows detect करने के लिए उपयोग किए जाते हैं।

### Thread Local Variables (TLV)

Mach-O files (macOS में executables का format) के context में **Thread Local Variables (TLV)** का उपयोग ऐसी variables declare करने के लिए किया जाता है जो multi-threaded application में **प्रत्येक thread** के लिए specific होती हैं। इससे प्रत्येक thread के पास किसी variable का अपना separate instance होता है, जिससे mutexes जैसे explicit synchronization mechanisms की आवश्यकता के बिना conflicts से बचने और data integrity बनाए रखने का एक तरीका मिलता है।

C और related languages में, आप **`__thread`** keyword का उपयोग करके thread-local variable declare कर सकते हैं। आपके example में यह इस प्रकार काम करता है:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
यह snippet `tlv_var` को एक thread-local variable के रूप में परिभाषित करता है। इस code को चलाने वाले प्रत्येक thread का अपना `tlv_var` होगा, और एक thread द्वारा `tlv_var` में किए गए बदलाव किसी अन्य thread के `tlv_var` को प्रभावित नहीं करेंगे।

Mach-O binary में, thread local variables से संबंधित data को specific sections में व्यवस्थित किया जाता है:

- **`__DATA.__thread_vars`**: इस section में thread-local variables से संबंधित metadata होता है, जैसे उनके types और initialization status।
- **`__DATA.__thread_bss`**: इस section का उपयोग उन thread-local variables के लिए किया जाता है जिन्हें explicitly initialize नहीं किया गया है। यह zero-initialized data के लिए अलग रखी गई memory का हिस्सा है।

Mach-O thread के exit होने पर thread-local variables को manage करने के लिए **`tlv_atexit`** नामक एक specific API भी प्रदान करता है। यह API आपको **destructors register** करने देती है—ये special functions होते हैं जो thread समाप्त होने पर thread-local data को clean up करते हैं।

### Threading Priorities

Thread priorities को समझने के लिए यह देखना आवश्यक है कि operating system यह कैसे तय करता है कि कौन-से threads चलने चाहिए और कब। यह निर्णय प्रत्येक thread को दिए गए priority level से प्रभावित होता है। macOS और Unix-like systems में इसे `nice`, `renice` और Quality of Service (QoS) classes जैसी concepts के माध्यम से handle किया जाता है।

#### Nice और Renice

1. **Nice:**
- किसी process का `nice` value एक number होता है जो उसकी priority को प्रभावित करता है। प्रत्येक process का nice value -20 (सबसे high priority) से 19 (सबसे low priority) तक होता है। Process create होने पर default nice value आमतौर पर 0 होता है।
- कम nice value (जो -20 के अधिक निकट हो) किसी process को अधिक "selfish" बनाता है, जिससे उसे अधिक high nice values वाले अन्य processes की तुलना में अधिक CPU time मिलता है।
2. **Renice:**
- `renice` एक command है जिसका उपयोग पहले से चल रहे process का nice value बदलने के लिए किया जाता है। इसका उपयोग processes की priority को dynamically adjust करने के लिए किया जा सकता है, जिससे नए nice values के आधार पर उनके CPU time allocation को बढ़ाया या घटाया जा सकता है।
- उदाहरण के लिए, यदि किसी process को अस्थायी रूप से अधिक CPU resources की आवश्यकता हो, तो आप `renice` का उपयोग करके उसका nice value कम कर सकते हैं।

#### Quality of Service (QoS) Classes

QoS classes thread priorities को handle करने का अधिक modern तरीका हैं, खासकर macOS जैसे systems में जो **Grand Central Dispatch (GCD)** support करते हैं। QoS classes developers को work को उसके importance या urgency के आधार पर अलग-अलग levels में **categorize** करने देती हैं। macOS इन QoS classes के आधार पर thread prioritization को automatically manage करता है:

1. **User Interactive:**
- यह class उन tasks के लिए है जो वर्तमान में user के साथ interact कर रहे हैं या अच्छा user experience प्रदान करने के लिए immediate results की आवश्यकता रखते हैं। Interface को responsive बनाए रखने के लिए इन tasks को highest priority दी जाती है (जैसे animations या event handling)।
2. **User Initiated:**
- ये वे tasks हैं जिन्हें user initiate करता है और जिनके लिए immediate results की अपेक्षा होती है, जैसे document खोलना या ऐसा button click करना जिसमें computations की आवश्यकता हो। इनकी priority high होती है, लेकिन user interactive से कम।
3. **Utility:**
- ये tasks long-running होते हैं और आमतौर पर progress indicator दिखाते हैं (जैसे files download करना या data import करना)। इनकी priority user-initiated tasks से कम होती है और इन्हें तुरंत complete होने की आवश्यकता नहीं होती।
4. **Background:**
- यह class उन tasks के लिए है जो background में operate करते हैं और user को दिखाई नहीं देते। इनमें indexing, syncing या backups जैसे tasks शामिल हो सकते हैं। इनकी priority सबसे कम होती है और system performance पर इनका प्रभाव minimal होता है।

QoS classes का उपयोग करके developers को exact priority numbers manage करने की आवश्यकता नहीं होती। इसके बजाय वे task की nature पर focus कर सकते हैं और system CPU resources को उसी के अनुसार optimize करता है।

इसके अलावा, अलग-अलग **thread scheduling policies** होती हैं, जो scheduling parameters का एक set specify करने के लिए flows करती हैं जिन्हें scheduler ध्यान में रखेगा। यह `thread_policy_[set/get]` का उपयोग करके किया जा सकता है। यह race condition attacks में useful हो सकता है।

## MacOS Process Abuse

MacOS, किसी भी अन्य operating system की तरह, **processes को interact, communicate और data share करने** के लिए कई methods और mechanisms प्रदान करता है। हालांकि ये techniques efficient system functioning के लिए essential हैं, threat actors इनका abuse करके **malicious activities perform** कर सकते हैं।

### Library Injection

Library Injection एक technique है जिसमें attacker **किसी process को malicious library load करने के लिए force** करता है। Inject होने के बाद library target process के context में run होती है, जिससे attacker को उस process जैसी ही permissions और access प्राप्त हो जाता है।


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking में software code के भीतर **function calls** या messages को **intercept** किया जाता है। Functions को hook करके attacker किसी process के **behavior को modify**, sensitive data observe या execution flow पर control प्राप्त कर सकता है।


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) उन अलग-अलग methods को refer करता है जिनके माध्यम से अलग processes **data share और exchange** करते हैं। हालांकि IPC कई legitimate applications के लिए fundamental है, इसका misuse process isolation को subvert करने, sensitive information को leak करने या unauthorized actions perform करने के लिए भी किया जा सकता है।


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Specific env variables के साथ execute की गई Electron applications process injection के प्रति vulnerable हो सकती हैं:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` और `--use-fake-ui-for-media-stream` flags का उपयोग करके **man in the browser attack** करना संभव है, जिससे keystrokes और traffic steal किए जा सकते हैं, cookies चुराई जा सकती हैं, pages में scripts inject की जा सकती हैं...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files किसी application के भीतर **user interface (UI) elements** और उनके interactions को **define** करती हैं। हालांकि, वे **arbitrary commands execute** कर सकती हैं और यदि किसी **NIB file को modify** किया गया हो, तो **Gatekeeper पहले से executed application को दोबारा execute होने से नहीं रोकता**। इसलिए, इनका उपयोग arbitrary programs से arbitrary commands execute करवाने के लिए किया जा सकता है:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

कुछ java capabilities (जैसे **`_JAVA_OPTS`** env variable) का abuse करके किसी java application से **arbitrary code/commands execute** करवाना संभव है।


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

**.Net debugging functionality का abuse** करके .Net applications में code inject करना संभव है (यह runtime hardening जैसे macOS protections द्वारा protected नहीं है)।


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Perl script से arbitrary code execute करवाने के विभिन्न options यहां देखें:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby env variables का abuse करके arbitrary scripts से arbitrary code execute करवाना भी संभव है:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

यदि **`PYTHONINSPECT`** environment variable set है, तो python process समाप्त होने के बाद python cli में चला जाएगा। Interactive session की शुरुआत में execute करने के लिए python script specify करने हेतु **`PYTHONSTARTUP`** का भी उपयोग किया जा सकता है।\
हालांकि, ध्यान दें कि जब **`PYTHONINSPECT`** interactive session create करता है, तब **`PYTHONSTARTUP`** script execute नहीं होगी।

**`PYTHONPATH`** और **`PYTHONHOME`** जैसे अन्य env variables भी python command से arbitrary code execute करवाने में useful हो सकते हैं।

ध्यान दें कि **`pyinstaller`** के साथ compiled executables इन environmental variables का उपयोग नहीं करेंगे, भले ही वे embedded python का उपयोग करके run हो रहे हों।

> [!CAUTION]
> कुल मिलाकर, मुझे environment variables का abuse करके python से arbitrary code execute करवाने का कोई तरीका नहीं मिला।\
> हालांकि, अधिकांश लोग **Hombrew** का उपयोग करके pyhton install करते हैं, जो default admin user के लिए pyhton को एक **writable location** में install करेगा। आप इसे इस तरह hijack कर सकते हैं:
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
> python run करते समय **root** भी इस code को execute करेगा।


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) एक open source **EndpointSecurity**-based application है जो process injection को detect और block करती है। यह इस बात का अच्छा reference है कि ES से वास्तव में कौन-से signals observable हैं, क्योंकि यह इन पर alert करती है:<sup>[1]</sup>

- Process exec पर **Injection environment variables**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` और `ELECTRON_RUN_AS_NODE`।
- **`task_for_pid`** calls — एक process द्वारा किसी अन्य process के task port के लिए request करना, जो उसमें injection करने की prerequisite है।
- **Electron debugging arguments** — `--inspect`, `--inspect-brk` और `--remote-debugging-port`, जो Electron app को debug mode में start करते हैं और किसी को भी उसमें attach होकर code run करने देते हैं।
- **Privilege levels के बीच symlink/hardlink creation** — classic "एक normal user के रूप में link बनाकर उसे privileged location पर point करना" primitive। ध्यान दें कि **symlinks पर alert किया जा सकता है, लेकिन उन्हें block नहीं किया जा सकता**: EndpointSecurity creation से पहले link destination expose नहीं करता।

### Calls made by other processes

[**इस blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) में आप जान सकते हैं कि किसी process में **code inject करने वाले अन्य processes** के बारे में information प्राप्त करने और फिर उस दूसरे process की information लेने के लिए **`task_name_for_pid`** function का उपयोग कैसे किया जा सकता है।<sup>[4]</sup>

ध्यान दें कि उस function को call करने के लिए आपका uid उस process को run करने वाले uid के समान होना चाहिए या आपके पास **root** access होना चाहिए (और यह process के बारे में information return करता है, code inject करने का तरीका नहीं)।

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
