# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

Bir process, çalışan bir executable'ın örneğidir; ancak process'ler code çalıştırmaz, bunları thread'ler çalıştırır. Bu nedenle **process'ler, çalışan thread'ler için yalnızca container'lardır** ve memory, descriptor, port, permission gibi kaynakları sağlar.

Geleneksel olarak process'ler, `fork` çağrılarak diğer process'lerin içinde başlatılırdı (PID 1 hariç). `fork`, mevcut process'in birebir kopyasını oluşturur ve ardından **child process** genellikle yeni executable'ı yükleyip çalıştırmak için **`execve`** çağırırdı. Daha sonra, herhangi bir memory kopyalama işlemi olmadan bu süreci hızlandırmak için **`vfork`** tanıtıldı.\
Ardından **`posix_spawn`**, **`vfork`** ve **`execve`** işlemlerini tek bir çağrıda birleştirerek ve flag'leri kabul ederek tanıtıldı:

- `POSIX_SPAWN_RESETIDS`: Effective id'leri real id'lere sıfırlar
- `POSIX_SPAWN_SETPGROUP`: Process group affiliation'ı ayarlar
- `POSUX_SPAWN_SETSIGDEF`: Signal default behaviour'ını ayarlar
- `POSIX_SPAWN_SETSIGMASK`: Signal mask'ını ayarlar
- `POSIX_SPAWN_SETEXEC`: Aynı process içinde Exec işlemi gerçekleştirir (daha fazla seçenekle `execve` gibi)
- `POSIX_SPAWN_START_SUSPENDED`: Suspended olarak başlatır
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlatır
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano allocator'ını kullanır
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Data segment'lerinde `rwx` kullanımına izin verir
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm file description'ları kapatır
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide'ının high bit'lerini randomize eder

Ayrıca `posix_spawn`, oluşturulan process'in çeşitli özelliklerini kontrol eden **`posix_spawnattr`** ayarlarını ve file descriptor'ları değiştiren **`posix_spawn_file_actions`** girdilerini kabul eder.

Bir process öldüğünde, `SIGCHLD` signal'i ile **return code'u parent process'e gönderir** (parent öldüyse yeni parent PID 1'dir). Parent'ın bu değeri `wait4()` veya `waitid()` çağrısıyla alması gerekir; bu gerçekleşene kadar child, hâlâ listelenen ancak kaynak tüketmeyen zombie state'inde kalır.

### PIDs

PID'ler, yani process identifier'lar, benzersiz bir process'i tanımlar. XNU'da **PID'ler** 64 bit'tir, monotonik olarak artar ve (abuse'ları önlemek için) **asla wrap olmaz**.

### Process Groups, Sessions & Coalations

**Process'ler**, yönetilmelerini kolaylaştırmak için **group'lara** eklenebilir. Örneğin, bir shell script içindeki command'lar aynı process group içinde olur; böylece örneğin kill kullanılarak **birlikte signal gönderilebilir**.\
Process'leri **session'lar içinde group'lamak** da mümkündür. Bir process bir session başlattığında (`setsid(2)`), child process'ler kendi session'larını başlatmadıkları sürece bu session içine yerleştirilir.

Coalition, Darwin'de process'leri gruplamanın başka bir yoludur. Bir process'in coalition'a katılması, pool resource'larına erişmesini, bir ledger paylaşmasını veya Jetsam ile karşılaşmasını sağlar. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Credentials & Personae

Her process, sistemdeki **privilege'larını tanımlayan credentials** barındırır. Her process'in bir primary `uid` ve bir primary `gid` değeri vardır (birden fazla group'a ait olabilir).\
Binary'de `setuid/setgid` biti varsa user ve group id'lerini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli function'lar vardır.

**`persona`** syscall'ı alternatif bir **credentials** kümesi sağlar. Bir persona'yı benimsemek, onun uid, gid ve group membership'larını **aynı anda** devralmak anlamına gelir. [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) içinde struct'ı bulmak mümkündür:
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

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir threading API'sinin parçası olan POSIX thread'lerini (`pthreads`) destekler. macOS'taki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu library, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev dahili olarak, macOS'un temel aldığı kernel olan XNU kernel'e özgü daha düşük seviyeli bir system call olan `bsdthread_create()` işlevini çağırır. Bu system call, scheduling policy'leri ve stack size dahil olmak üzere thread davranışını belirleyen `pthread_attr`'dan (attributes) türetilen çeşitli flag'leri alır.
- **Varsayılan Stack Size:** Yeni thread'ler için varsayılan stack size 512 KB'dir. Bu boyut tipik işlemler için yeterlidir ancak daha fazla veya daha az alana ihtiyaç duyulursa thread attributes aracılığıyla ayarlanabilir.
3. **Thread Initialization:** `__pthread_init()` işlevi thread kurulumu sırasında kritik öneme sahiptir ve stack'in konumu ile size'ı hakkındaki bilgileri içerebilen environment variable'ları ayrıştırmak için `env[]` argument'ını kullanır.

#### macOS'ta Thread Sonlandırma

1. **Thread'lerden Çıkma:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, bir thread'in gerekli cleanup işlemlerini gerçekleştirerek temiz biçimde çıkmasını ve joiner'lara bir return value göndermesini sağlar.
2. **Thread Cleanup:** `pthread_exit()` çağrıldığında, ilişkili tüm thread structure'larının kaldırılmasını yöneten `pthread_terminate()` işlevi çağrılır. Mach thread port'larını (Mach, XNU kernel'deki communication subsystem'dir) deallocate eder ve thread ile ilişkili kernel-level structure'larını kaldıran bir syscall olan `bsdthread_terminate`'ı çağırır.

#### Synchronization Mechanism'leri

macOS, shared resource'lara erişimi yönetmek ve race condition'ları önlemek için çeşitli synchronization primitive'leri sağlar. Bunlar, data integrity ve system stability sağlamak için multi-threading environment'larında kritik öneme sahiptir:

1. **Mutex'ler:**
- **Regular Mutex (Signature: 0x4D555458):** 60 byte memory footprint'e sahip standart mutex (mutex için 56 byte ve signature için 4 byte).
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex'e benzer ancak daha hızlı işlemler için optimize edilmiştir ve yine 60 byte boyutundadır.
2. **Condition Variable'lar:**
- Belirli condition'ların gerçekleşmesini beklemek için kullanılır; boyutu 44 byte'tır (40 byte artı 4 byte signature).
- **Condition Variable Attributes (Signature: 0x434e4441):** 12 byte boyutundaki condition variable'lar için configuration attributes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Bir initialization code parçasının yalnızca bir kez yürütülmesini sağlar. Boyutu 12 byte'tır.
4. **Read-Write Lock'lar:**
- Birden fazla reader'a veya aynı anda tek bir writer'a izin vererek shared data'ya verimli erişim sağlar.
- **Read Write Lock (Signature: 0x52574c4b):** 196 byte boyutundadır.
- **Read Write Lock Attributes (Signature: 0x52574c41):** Read-write lock'lar için 20 byte boyutundaki attributes.

> [!TIP]
> Bu object'lerin son 4 byte'ı overflow'ları tespit etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O dosyaları (macOS'taki executable'ların formatı) bağlamındaki **Thread Local Variables (TLV)**, multi-threaded bir application'daki **her thread'e** özgü variable'ları tanımlamak için kullanılır. Bu, her thread'in bir variable'ın kendine ait ayrı instance'ına sahip olmasını sağlar ve mutex gibi explicit synchronization mechanism'lerine ihtiyaç duymadan conflict'leri önlemek ve data integrity'yi korumak için bir yöntem sunar.

C ve ilişkili language'lerde, `__thread` keyword'ünü kullanarak bir thread-local variable tanımlayabilirsiniz. Örneğimizde şu şekilde çalışır:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Bu snippet, `tlv_var` değişkenini thread-local bir değişken olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'deki `tlv_var` değişkenini etkilemez.

Mach-O binary içinde thread-local değişkenlerle ilgili veriler belirli section'larda düzenlenir:

- **`__DATA.__thread_vars`**: Bu section, thread-local değişkenler hakkındaki türleri ve initialization durumlarını gibi metadata bilgilerini içerir.
- **`__DATA.__thread_bss`**: Bu section, açıkça initialize edilmemiş thread-local değişkenler için kullanılır. Sıfır ile initialize edilen veriler için ayrılmış bir bellek bölümüdür.

Mach-O ayrıca thread sonlandığında thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API sağlar. Bu API, bir thread sonlandığında thread-local verilerini temizleyen özel fonksiyonlar olan **destructor'ları register etmenize** olanak tanır.

### Threading Priorities

Thread priority'lerini anlamak, işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmayı gerektirir. Bu karar, her thread'e atanan priority level'dan etkilenir. macOS ve Unix-like sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) class'ları gibi kavramlarla gerçekleştirilir.

#### Nice and Renice

1. **Nice:**
- Bir process'in `nice` değeri, priority'sini etkileyen bir sayıdır. Her process'in -20 (en yüksek priority) ile 19 (en düşük priority) arasında bir nice değeri vardır. Bir process oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
- Daha düşük bir nice değeri (-20'ye daha yakın) bir process'i daha "bencil" hale getirerek, daha yüksek nice değerlerine sahip diğer process'lere kıyasla daha fazla CPU zamanı almasını sağlar.
2. **Renice:**
- `renice`, zaten çalışan bir process'in nice değerini değiştirmek için kullanılan bir command'dir. Bu, yeni nice değerlerine göre CPU zamanı tahsisini artırmak veya azaltmak amacıyla process'lerin priority'sini dinamik olarak ayarlamak için kullanılabilir.
- Örneğin, bir process geçici olarak daha fazla CPU kaynağına ihtiyaç duyuyorsa, `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Classes

QoS class'ları, özellikle **Grand Central Dispatch (GCD)** destekleyen macOS gibi sistemlerde thread priority'lerini yönetmek için daha modern bir yaklaşımdır. QoS class'ları, geliştiricilerin çalışmaları önem veya aciliyetlerine göre farklı seviyelerde **categorize etmelerini** sağlar. macOS, bu QoS class'larına göre thread prioritization işlemini otomatik olarak yönetir:

1. **User Interactive:**
- Bu class, kullanıcıyla etkileşim halinde olan veya iyi bir user experience sağlamak için anında sonuç gerektiren task'ler içindir. Interface'in responsive kalması için bu task'lere en yüksek priority verilir (ör. animation'lar veya event handling).
2. **User Initiated:**
- Kullanıcının başlattığı ve bir document açmak veya computation gerektiren bir button'a tıklamak gibi anında sonuç beklediği task'lerdir. Bunlar yüksek priority'ye sahiptir ancak user interactive seviyesinin altındadır.
3. **Utility:**
- Bunlar uzun süre çalışan ve genellikle bir progress indicator gösteren task'lerdir (ör. file download etme veya data import etme). User-initiated task'lere göre daha düşük priority'ye sahiptirler ve hemen tamamlanmaları gerekmez.
4. **Background:**
- Bu class, background'da çalışan ve kullanıcı tarafından görünmeyen task'ler içindir. Indexing, syncing veya backup gibi task'ler olabilir. En düşük priority'ye ve system performance üzerinde minimum etkiye sahiptirler.

QoS class'larını kullanan geliştiricilerin exact priority number'larını yönetmesi gerekmez; bunun yerine task'in niteliğine odaklanmaları yeterlidir ve system CPU kaynaklarını buna göre optimize eder.

Bunlara ek olarak, scheduler'ın dikkate alacağı bir scheduling parameter seti belirtmek için kullanılan farklı **thread scheduling policies** bulunur. Bu işlem `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition attack'lerinde yararlı olabilir.

## macOS Process Abuse

macOS, **process'lerin etkileşime girmesi, iletişim kurması ve data paylaşması** için birçok mekanizma sağlar. Bu mekanizmalar normal system operation için gerekli olsa da attacker'lar bunları injection, code execution veya data access amacıyla abuse edebilir.

### Library Injection

Library Injection, bir attacker'ın **bir process'i malicious bir library yüklemeye zorladığı** bir tekniktir. Injection gerçekleştirildikten sonra library, target process'in context'inde çalışarak attacker's process ile aynı permissions ve access seviyelerini sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking, bir software code içindeki **function call'larını** veya message'ları **intercept etmeyi** içerir. Bir attacker function'ları hook'layarak bir process'in **behavior'ını değiştirebilir**, sensitive data'yı gözlemleyebilir veya execution flow'un kontrolünü ele geçirebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı process'lerin **data paylaşmasını ve exchange etmesini** sağlayan farklı yöntemleri ifade eder. IPC birçok legitimate application için temel nitelikte olsa da process isolation'ı bypass etmek, sensitive information'ı leak etmek veya unauthorized action'lar gerçekleştirmek için de misuse edilebilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env variable'larla çalıştırılan Electron application'ları process injection'a karşı vulnerable olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanarak **man in the browser attack** gerçekleştirmek mümkündür; bu attack keystroke'ları ve traffic'i çalmaya, cookie'leri ele geçirmeye, page'lere script inject etmeye olanak tanır...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB file'ları bir application içindeki **user interface (UI) element'lerini** ve bunların interaction'larını **tanımlar**. Ancak arbitrary command'ler **execute edebilirler** ve **NIB file modified** edilirse **Gatekeeper zaten execute edilmiş bir application'ın yeniden execute edilmesini engellemez**. Bu nedenle arbitrary program'ların arbitrary command'ler execute etmesini sağlamak için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** veya **`JDK_JAVA_OPTIONS`** üzerinden JVM option'larını inject etmek ve application başlamadan önce bir Java veya native agent yüklemek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

`Main`'den önce **`DOTNET_STARTUP_HOOKS`** üzerinden .NET application'larına code inject etmek veya prerequisites mevcut olduğunda .NET debugging functionality'yi abuse etmek mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Interactive olmayan Bash **`BASH_ENV`** dosyasını okur; zsh **`$ZDOTDIR/.zshenv`** dosyasını okur; fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki configuration'ı okur. Bunların her biri intended command'dan önce controlled bir startup file execute edebilir:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, **`auto_prepend_file`** directive'i target script'ten önce execute edilen controlled bir PHP configuration yükleyebilir.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Standalone Lua interpreter, target script'i process etmeden önce **`LUA_INIT`** üzerinden (veya version-specific variant'ı üzerinden) code ya da `@file` execute eder.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R code içeren startup profile'larını redirect eder. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ile birlikte bir R library path kullanılarak bunun yerine installed bir package auto-load edilebilir.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyası otomatik olarak execute edilen depot'u redirect eder.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, bir payload file gerektirmeden Erlang VM'e **`-eval`** expression'ı inject edebilir; Elixir workload'ları genellikle aynı VM'i başlatır.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave startup script'lerini redirect eder.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

macOS ve Linux'ta **`XDG_CONFIG_HOME`**, `pwsh` başlatıldığında execute edilen PowerShell user profile'larını redirect edebilir.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin arbitrary code execute etmesini sağlamak için farklı option'ları inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Arbitrary script'lerin arbitrary code execute etmesini sağlamak için ruby env variable'larını abuse etmek de mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** ve **`BROWSER`** standard-library chain'i, warning-filter parsing sırasında bir command execute edebilir. File-backed alternatifte `sitecustomize.py`, **`PYTHONPATH`** üzerine yerleştirilir; böylece normal `site` initialization, target script'ten önce bu file'ı import eder. **`PYTHONSTARTUP`** gibi yalnızca interactive kullanımda geçerli olan variable'ların uygulanabilirliği daha sınırlıdır.

`pyinstaller` ile compile edilmiş executable'ların embedded python kullanarak çalışıyor olsalar bile bu environment variable'larını kullanmayacağını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

Ayrı olarak, Homebrew genellikle Python'ı `/opt/homebrew` altında install eder; burada local `admin` group üyeleri launcher'ı replace edebilir. Bu, environment-variable injection yerine writable-binary hijack'tir; exploitable olarak değerlendirmeden önce ownership ve ACL'leri verify edin.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı detect edip block eden, open-source ve **EndpointSecurity** tabanlı bir application'dır. Endpoint Security üzerinden hangi signal'ların gözlemlenebildiği konusunda iyi bir reference'tır; şu durumlarda alert verir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Process exec sırasında **injection environment variable'ları**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** call'ları — bir process'in başka bir process'in task port'unu istemesi; bu, o process'e injection gerçekleştirmek için prerequisite'tir.
- **Electron debugging argument'ları** — Electron application'ını debug mode'da başlatan ve herkesin bağlanarak code execute etmesine olanak tanıyan `--inspect`, `--inspect-brk` ve `--remote-debugging-port`.<sup>[[3]](#references)</sup>
- **Privilege level'lar arasında symlink/hardlink oluşturulması** — klasik "normal user olarak bir link oluşturup privileged bir location'ı göstermesini sağlama" primitive'i. **Symlink'ler alert edilebilir ancak block edilemez**: EndpointSecurity, link oluşturulmadan önce link destination'ını expose etmez.

### Calls made by other processes

[**this blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) içinde, başka **process'lerin bir process'e code inject ettiğine** dair bilgi almak ve ardından diğer process hakkında bilgi edinmek için **`task_name_for_pid`** function'ının nasıl kullanılabileceğini görebilirsiniz.<sup>[[4]](#references)</sup>

Bu function'ı call etmek için process'i çalıştıran user ile **aynı uid'ye** veya **root** yetkisine sahip olmanız gerekir (ve function, code inject etmenin bir yolunu değil process hakkında bilgi döndürür).

## References

- [1] [Shield — open-source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron apps neden secret'larını confidential olarak saklayamaz: --inspect option'ı](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Task modification'larını detect etme](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
