# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

Bir process, çalışan bir executable'ın instance'ıdır; ancak process'ler code çalıştırmaz, bunu thread'ler yapar. Bu nedenle **process'ler, çalışan thread'ler için yalnızca container'lardır** ve memory, descriptor, port, permission gibi kaynakları sağlar.

Geleneksel olarak process'ler, **`fork`** çağrısı yapılarak diğer process'lerin içinde başlatılırdı (PID 1 hariç). Bu çağrı mevcut process'in birebir kopyasını oluşturur ve ardından **child process** genellikle yeni executable'ı yükleyip çalıştırmak için **`execve`** çağrısı yapardı. Daha sonra bu process'i herhangi bir memory kopyalama işlemi olmadan hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından **`posix_spawn`**, **`vfork`** ve **`execve`** işlemlerini tek bir çağrıda birleştirerek ve flag'leri kabul ederek kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Effective id'leri real id'lere sıfırlar
- `POSIX_SPAWN_SETPGROUP`: Process group affiliation'ını ayarlar
- `POSUX_SPAWN_SETSIGDEF`: Signal default behaviour'ını ayarlar
- `POSIX_SPAWN_SETSIGMASK`: Signal mask'ını ayarlar
- `POSIX_SPAWN_SETEXEC`: Aynı process içinde Exec işlemi yapar (`execve` gibi, ancak daha fazla option ile)
- `POSIX_SPAWN_START_SUSPENDED`: Suspended olarak başlatır
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlatır
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano allocator'ını kullanır
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Data segment'lerinde `rwx` kullanımına izin verir
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm file description'ları kapatır
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide'ın high bit'lerini randomize eder

Ayrıca `posix_spawn`, oluşturulan process'in özelliklerini kontrol eden **`posix_spawnattr`** ayarlarını ve file descriptor'ları değiştiren **`posix_spawn_file_actions`** girişlerini kabul eder.

Bir process sonlandığında **return code'u parent process'e** (parent sonlandıysa yeni parent PID 1'dir) `SIGCHLD` signal'i ile gönderir. Parent'ın bu değeri `wait4()` veya `waitid()` çağrısıyla alması gerekir; bu gerçekleşene kadar child, hâlâ listelenen ancak resource tüketmeyen bir zombie state'inde kalır.

### PIDs

PID'ler, yani process identifier'lar, benzersiz bir process'i tanımlar. XNU'da **PID'ler** 64-bit'tir, monotonik olarak artar ve (abuse'ları önlemek için) **asla wrap olmaz**.

### Process Groups, Sessions & Coalations

**Process'ler**, onları yönetmeyi kolaylaştırmak için **group'lar** içine yerleştirilebilir. Örneğin bir shell script'indeki command'lar aynı process group içinde olur; böylece örneğin kill kullanılarak **birlikte signal gönderilebilir**.\
Process'leri **session'lar içinde group'lamak** da mümkündür. Bir process bir session başlattığında (`setsid(2)`), child process'ler kendi session'larını başlatmadıkları sürece bu session içine yerleştirilir.

Coalition, Darwin'de process'leri group'lamanın başka bir yoludur. Bir process'in coalition'a katılması, pool resource'larına erişmesine, bir ledger'ı paylaşmasına veya Jetsam ile karşılaşmasına olanak tanır. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Credentials & Personae

Her process, sistemdeki **privilege'larını tanımlayan** **credential'lara** sahiptir. Her process'in bir primary `uid`'si ve bir primary `gid`'si vardır (birden fazla group'a ait olabilir).\
Binary `setuid/setgid` bit'ine sahipse user ve group id'sini değiştirmek de mümkündür.\
**Yeni uid/gid'ler ayarlamak** için çeşitli function'lar vardır.

**`persona`** syscall'ı alternatif bir **credential** set'i sağlar. Bir persona'yı benimsemek, onun uid, gid ve group membership'lerini **aynı anda** devralmak anlamına gelir. [**Source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) içinde struct'ı bulmak mümkündür:
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
## Threads Temel Bilgileri

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir threading API'sinin parçası olan POSIX thread'lerini (`pthreads`) destekler. macOS'taki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu kütüphane, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev dahili olarak, XNU kernel'ine (macOS'un temel aldığı kernel) özgü daha düşük seviyeli bir system call olan `bsdthread_create()` işlevini çağırır. Bu system call, scheduling policy'leri ve stack size da dahil olmak üzere thread davranışını belirleyen `pthread_attr`'dan (attributes) türetilen çeşitli flag'leri alır.
- **Varsayılan Stack Size:** Yeni thread'ler için varsayılan stack size 512 KB'dir. Bu değer tipik işlemler için yeterlidir, ancak daha fazla veya daha az alana ihtiyaç duyulması halinde thread attributes aracılığıyla ayarlanabilir.
3. **Thread Initialization:** `__pthread_init()` işlevi, thread kurulumu sırasında kritik bir rol oynar ve stack'in konumu ile size bilgilerini içerebilen environment variable'ları ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'ta Thread Termination

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, bir thread'in gerekli temizleme işlemlerini gerçekleştirerek düzgün şekilde çıkmasını ve herhangi bir joiner'a dönüş değeri göndermesini sağlar.
2. **Thread Cleanup:** `pthread_exit()` çağrıldığında, ilişkili tüm thread yapılarını kaldıran `pthread_terminate()` işlevi çağrılır. Bu işlev Mach thread port'larını serbest bırakır (Mach, XNU kernel'indeki iletişim alt sistemidir) ve thread ile ilişkili kernel seviyesindeki yapıları kaldıran bir syscall olan `bsdthread_terminate` işlevini çağırır.

#### Synchronization Mechanisms

Paylaşılan kaynaklara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli synchronization primitive'leri sağlar. Bunlar, data integrity ve system stability sağlamak amacıyla multi-threading ortamlarında kritik öneme sahiptir:

1. **Mutex'ler:**
- **Regular Mutex (Signature: 0x4D555458):** 60 byte memory footprint'e sahip standart mutex (mutex için 56 byte ve signature için 4 byte).
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex'e benzer, ancak daha hızlı işlemler için optimize edilmiştir ve boyutu yine 60 byte'tır.
2. **Condition Variables:**
- Belirli condition'ların gerçekleşmesini beklemek için kullanılır; boyutu 44 byte'tır (40 byte artı 4 byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** 12 byte boyutundaki condition variable'lar için configuration attributes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Bir initialization code parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 byte'tır.
4. **Read-Write Locks:**
- Birden fazla reader'a veya aynı anda tek bir writer'a izin vererek paylaşılan data'ya verimli erişim sağlar.
- **Read Write Lock (Signature: 0x52574c4b):** Boyutu 196 byte'tır.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write lock'lar için 20 byte boyutundaki attributes.

> [!TIP]
> Bu object'lerin son 4 byte'ı overflow'ları tespit etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O dosyaları (macOS'taki executable'ların formatı) bağlamında **Thread Local Variables (TLV)**, multi-threaded bir application'daki **her thread'e** özgü variable'ları tanımlamak için kullanılır. Bu, her thread'in bir variable'ın kendi ayrı instance'ına sahip olmasını sağlar ve mutex'ler gibi açık synchronization mechanism'larına ihtiyaç duymadan conflict'leri önlemek ve data integrity'yi korumak için bir yol sunar.

C ve ilgili dillerde, **`__thread`** keyword'ünü kullanarak thread-local variable tanımlayabilirsiniz. Örneğinizde şu şekilde çalışır:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Bu snippet, `tlv_var` değişkenini thread-local bir değişken olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'deki `tlv_var` değişkenini etkilemez.

Mach-O binary içinde thread-local değişkenlerle ilgili veriler belirli section'larda düzenlenir:

- **`__DATA.__thread_vars`**: Bu section, thread-local değişkenlerin türleri ve initialization durumu gibi metadata bilgilerini içerir.
- **`__DATA.__thread_bss`**: Bu section, açıkça initialize edilmemiş thread-local değişkenler için kullanılır. Sıfırla initialize edilen veriler için ayrılmış memory'nin bir parçasıdır.

Mach-O ayrıca thread sonlandığında thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, bir thread sonlandığında thread-local verileri temizleyen özel function'lar olan **destructor**'ları **register** etmenize olanak tanır.

### Threading Priorities

Thread priority'lerini anlamak, operating system'in hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmayı gerektirir. Bu karar, her thread'e atanan priority level'dan etkilenir. macOS ve Unix-like sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) class'ları gibi kavramlar kullanılarak gerçekleştirilir.

#### Nice and Renice

1. **Nice:**
- Bir process'in `nice` değeri, priority'sini etkileyen bir sayıdır. Her process, -20 (en yüksek priority) ile 19 (en düşük priority) arasında bir nice değerine sahiptir. Bir process oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
- Daha düşük bir nice değeri (-20'ye daha yakın), bir process'i daha "selfish" hale getirir ve daha yüksek nice değerlerine sahip diğer process'lere kıyasla daha fazla CPU zamanı almasını sağlar.
2. **Renice:**
- `renice`, hâlihazırda çalışan bir process'in nice değerini değiştirmek için kullanılan bir command'dir. Bu, yeni nice değerlerine göre CPU zamanı tahsisini artırmak veya azaltmak amacıyla process'lerin priority'sini dinamik olarak ayarlamak için kullanılabilir.
- Örneğin, bir process'in geçici olarak daha fazla CPU kaynağına ihtiyacı varsa, `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Classes

QoS class'ları, özellikle **Grand Central Dispatch (GCD)** desteğine sahip macOS gibi sistemlerde thread priority'lerini yönetmek için daha modern bir yaklaşımdır. QoS class'ları, developer'ların işleri önem veya aciliyetlerine göre farklı level'lara **categorize** etmelerini sağlar. macOS, bu QoS class'larına göre thread prioritization işlemini otomatik olarak yönetir:

1. **User Interactive:**
- Bu class, hâlihazırda user ile etkileşim hâlinde olan veya iyi bir user experience sağlamak için anında sonuç gerektiren task'ler içindir. Interface'in responsive kalması için bu task'lere en yüksek priority verilir (ör. animation'lar veya event handling).
2. **User Initiated:**
- Bir document açmak veya computation gerektiren bir button'a tıklamak gibi user'ın başlattığı ve anında sonuç beklediği task'lerdir. Bunlar yüksek priority'ye sahiptir ancak user interactive seviyesinin altındadır.
3. **Utility:**
- Bunlar uzun süren ve genellikle bir progress indicator gösteren task'lerdir (ör. file download etme veya data import etme). User-initiated task'lerden daha düşük priority'ye sahiptirler ve hemen tamamlanmaları gerekmez.
4. **Background:**
- Bu class, background'da çalışan ve user tarafından görünmeyen task'ler içindir. Indexing, syncing veya backup gibi task'ler buna örnektir. En düşük priority'ye ve system performance üzerinde minimum etkiye sahiptirler.

QoS class'larını kullanan developer'ların kesin priority numaralarını yönetmesi gerekmez; bunun yerine task'in niteliğine odaklanabilirler ve system CPU kaynaklarını buna göre optimize eder.

Ayrıca scheduler'ın dikkate alacağı bir scheduling parameter set'i belirtmek için kullanılan farklı **thread scheduling policies** vardır. Bu işlem `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition attack'lerinde faydalı olabilir.

## macOS Process Abuse

macOS, **process'lerin etkileşime girmesi, iletişim kurması ve data paylaşması** için birçok mekanizma sağlar. Bu mekanizmalar normal system operation için gerekli olsa da attacker'lar bunları injection, code execution veya data access amacıyla abuse edebilir.

### Library Injection

Library Injection, attacker'ın **bir process'i malicious bir library yüklemeye zorladığı** bir technique'tir. Inject edildikten sonra library, hedef process'in context'inde çalışır ve attacker'a process ile aynı permission ve access seviyelerini sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking, bir software code içindeki **function call'larını** veya mesajları **intercept etmeyi** içerir. Function'ları hook'layarak attacker, bir process'in **davranışını değiştirebilir**, sensitive data'yı gözlemleyebilir veya execution flow'un kontrolünü ele geçirebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı process'lerin **data paylaşmasını ve exchange etmesini** sağlayan farklı method'ları ifade eder. IPC birçok legitimate application için temel nitelikte olsa da process isolation'ı subvert etmek, sensitive information'ı leak etmek veya unauthorized action gerçekleştirmek amacıyla da misuse edilebilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env variable'ları kullanarak çalıştırılan Electron application'ları process injection'a karşı vulnerable olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

**man in the browser attack** gerçekleştirmek için `--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanmak mümkündür; bu, keystroke'ları, traffic'i ve cookie'leri çalmaya, page'lere script inject etmeye olanak tanır...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB file'ları bir application içindeki **user interface (UI) element'lerini** ve bunların etkileşimlerini **tanımlar**. Ancak arbitrary command'ler **execute edebilirler** ve bir **NIB file değiştirilirse**, **Gatekeeper zaten execute edilmiş bir application'ın yeniden execute edilmesini engellemez**. Bu nedenle arbitrary program'ları arbitrary command'ler execute ettirmek için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Application başlamadan önce **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** veya **`JDK_JAVA_OPTIONS`** üzerinden JVM option'larını inject etmek ve bir Java veya native agent yüklemek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (file) veya `--import data:text/javascript,…` (fileless, Node ≥ 20.6) aracılığıyla attacker JavaScript'ini preload eder; **`NODE_REPL_EXTERNAL_MODULE`** bir module'ü interactive REPL içine yükler ve **`ELECTRON_RUN_AS_NODE`**, bunların tamamını Electron binary'leri üzerinde yeniden etkinleştirir.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main`'den önce **`DOTNET_STARTUP_HOOKS`** aracılığıyla .NET application'larına code inject etmek veya prerequisites mevcut olduğunda .NET debugging functionality'yi abuse etmek mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bash **`BASH_ENV`** dosyasını okur; interactive POSIX shell'leri **`ENV`** dosyasını okur; zsh **`$ZDOTDIR/.zshenv`** dosyasını okur; fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki configuration'ı okur. Bunların her biri, intended command'den önce controlled bir startup file execute edebilir. Bash ayrıca xtrace etkinleştirildiğinde (ör. inherited **`SHELLOPTS=xtrace`**) **`PS4`** içine yerleştirilmiş bir command substitution'ı çalıştırır:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, **`auto_prepend_file`** değeri target script'ten önce execute edilen controlled bir PHP configuration yükleyebilir.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Standalone Lua interpreter, target script'i process etmeden önce **`LUA_INIT`** (veya version-specific variant'ı) üzerinden code ya da bir `@file` execute eder.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R code içeren startup profile'larını redirect eder. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ve bir R library path kullanılarak bunun yerine installed bir package otomatik olarak load edilebilir.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyası otomatik olarak execute edilen depot'u redirect eder.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, payload file gerektirmeden bir Erlang VM **`-eval`** expression'ı inject edebilir; Elixir workload'ları genellikle aynı VM'i başlatır.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave startup script'lerini redirect eder.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` cross-platform bir .NET app olduğundan, çeşitli environment variable'lar command öncesi execution sağlar: **`XDG_CONFIG_HOME`**, startup sırasında çalışan profile script'lerini redirect eder; **`PSModulePath`**, module auto-loading işlemini hijack eder (yerleştirilmiş bir `.psm1`, import sırasında çalışır ve built-in cmdlet'leri shadow edebilir); .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** ve **`DOTNET_STARTUP_HOOKS`** variable'ları ise `Main`'den önce attacker code'unu process içine yükler.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin aşağıdaki yöntemlerle arbitrary code execute etmesini sağlamak için farklı option'ları inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary script'lerin arbitrary code execute etmesini sağlamak için Ruby env variable'larını (**`RUBYOPT`**, **`RUBYLIB`**) abuse etmek de mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** ve **`BROWSER`** standard-library chain'i, warning-filter parsing sırasında bir command execute edebilir. File-backed alternative olarak **`PYTHONPATH`** üzerine `sitecustomize.py` yerleştirilir; böylece normal `site` initialization, target script'ten önce bunu import eder. **`PYTHONBREAKPOINT`**, code `breakpoint()`'a ulaştığında seçilen callable/module'ü çalıştırır. **`PYTHONSTARTUP`** gibi yalnızca interactive olan variable'ların uygulanabilirliği daha sınırlıdır.

`pyinstaller` ile compile edilmiş executable'ların embedded python kullanarak çalışsalar bile bu environment variable'ları kullanmayacağını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (ve fallback olarak **`EXINIT`**), normal startup sırasında Ex command'leri olarak execute edilir; bu nedenle controlled bir environment ile victim Vim/Neovim açtığında `:!cmd` / `:call system(...)` code execution sağlar:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ayrı olarak Homebrew, Python'ı genellikle `/opt/homebrew` altında kurar; burada local `admin` group üyeleri launcher'ı değiştirebilir. Bu, environment-variable injection yerine writable-binary hijack'tir; exploitable olarak değerlendirmeden önce ownership ve ACL'leri doğrulayın.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı detect edip block eden, open-source ve **EndpointSecurity** tabanlı bir application'dır. Endpoint Security üzerinden hangi signal'ların gözlemlenebilir olduğunu anlamak için iyi bir reference'tır; şu durumlarda alert üretir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec sırasında **injection environment variable'ları**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** call'ları — bir process'in başka bir process'in task port'unu istemesi; bu, o process'e injection yapmanın prerequisite'idir.
- **Electron debugging argument'ları** — Electron app'ini debug mode'da başlatan ve herkesin app'e attach olup code çalıştırmasına izin veren `--inspect`, `--inspect-brk` ve `--remote-debugging-port`.<sup>[[3]](#references)</sup>
- **Privilege level'lar arasında symlink/hardlink oluşturulması** — klasik "normal user olarak bir link yerleştirip privileged bir location'ı göstermesini sağlama" primitive'i. **Symlink'ler alert edilebilir ancak block edilemez**: EndpointSecurity, oluşturulmadan önce link destination'ını expose etmez.

### Calls made by other processes

[**Bu blog post'ta**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), diğer **process'lerin bir process'e code inject ettiğini** tespit etmek ve ardından bu diğer process hakkında bilgi almak için **`task_name_for_pid`** function'ının nasıl kullanılabileceğini görebilirsiniz.<sup>[[4]](#references)</sup>

Bu function'ı çağırmak için process'i çalıştıran user ile **aynı uid**'ye veya **root** yetkisine sahip olmanız gerekir (function, code inject etmenin bir yolunu değil, process hakkında bilgi döndürür).

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
